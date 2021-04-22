/*
 * Copyright 2018 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
package conflux

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	cfxclient "github.com/Conflux-Chain/go-conflux-sdk"
	cfxtypes "github.com/Conflux-Chain/go-conflux-sdk/types"
	"github.com/Conflux-Chain/go-conflux-sdk/types/cfxaddress"
	"github.com/assetsadapterstore/conflux-adapter/conflux_addrdec"
	"github.com/assetsadapterstore/conflux-adapter/conflux_rpc"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/common"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcom "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/shopspring/decimal"
	"math/big"
	"sort"
	"strings"
)

type WalletManager struct {
	openwallet.AssetsAdapterBase
	CfxClient               *cfxclient.Client
	RawClient               *ethclient.Client               //原生ETH客户端
	WalletClient            *conflux_rpc.Client             // 节点客户端
	Config                  *WalletConfig                   //钱包管理配置
	Blockscanner            openwallet.BlockScanner         //区块扫描器
	Decoder                 openwallet.AddressDecoderV2     //地址编码器
	TxDecoder               openwallet.TransactionDecoder   //交易单编码器
	ContractDecoder         openwallet.SmartContractDecoder //智能合约解释器
	Log                     *log.OWLogger                   //日志工具
	CustomAddressEncodeFunc func(address string) string     //自定义地址转换算法
	CustomAddressDecodeFunc func(address string) string     //自定义地址转换算法
}

func NewWalletManager() *WalletManager {
	wm := WalletManager{}
	wm.Config = NewConfig(Symbol)
	wm.Blockscanner = NewBlockScanner(&wm)
	wm.Decoder = &conflux_addrdec.Default
	wm.TxDecoder = NewTransactionDecoder(&wm)
	wm.ContractDecoder = &CfxContractDecoder{wm: &wm}
	wm.Log = log.NewOWLogger(wm.Symbol())
	wm.CustomAddressEncodeFunc = CustomAddressEncode
	wm.CustomAddressDecodeFunc = CustomAddressDecode

	return &wm
}

func (wm *WalletManager) GetTransactionCount(addr string) (uint64, error) {
	addr = wm.CustomAddressDecodeFunc(addr)
	params := []interface{}{
		AppendOxToAddress(addr),
		"latest",
	}

	if wm.WalletClient == nil {
		return 0, fmt.Errorf("wallet client is not initialized")
	}

	result, err := wm.WalletClient.Call("cfx_getTransactionCount", params)
	if err != nil {
		return 0, err
	}

	nonceStr := result.String()
	return hexutil.DecodeUint64(nonceStr)
}

func (wm *WalletManager) GetTransactionReceipt(transactionId string) (*TransactionReceipt, error) {

	txhash := cfxtypes.Hash(transactionId)
	receipt, err := wm.CfxClient.GetTransactionReceipt(txhash)

	if err != nil {
		return nil, err
	}

	txReceipt := &TransactionReceipt{CFXReceipt: receipt}

	return txReceipt, nil

}

func (wm *WalletManager) GetTransactionByHash(txid string) (*BlockTransaction, error) {

	transaction, err := wm.CfxClient.GetTransactionByHash(cfxtypes.Hash(txid))

	if err != nil {
		return nil, err
	}
	tx := CreateBlockTransaction(transaction, wm.Decimal())
	return tx, nil
}

func (wm *WalletManager) GetBlockByNum(blockNum uint64) (*cfxtypes.Block, error) {

	result, err := wm.CfxClient.GetBlockByEpoch(cfxtypes.NewEpochNumber(cfxtypes.NewBigInt(blockNum)))
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (wm *WalletManager) GetBlockSummaryByNum(blockNum uint64) (*cfxtypes.BlockSummary, error) {

	result, err := wm.CfxClient.GetBlockSummaryByEpoch(cfxtypes.NewEpochNumber(cfxtypes.NewBigInt(blockNum)))
	if err != nil {
		return nil, err
	}

	return result, nil
}

func encodeKey(cids []string) []byte {
	buffer := new(bytes.Buffer)
	for _, c := range cids {
		// bytes.Buffer.Write() err is documented to be always nil.
		_, _ = buffer.Write([]byte(c))
	}

	newHash := owcrypt.Hash(buffer.Bytes(), 0, owcrypt.HASH_ALG_SHA256)
	return newHash
}

func (wm *WalletManager) GetTransByNum(blockNum uint64) ([]cfxtypes.Transaction, error) {

	result, err := wm.CfxClient.GetBlocksByEpoch(cfxtypes.NewEpochNumber(cfxtypes.NewBigInt(blockNum)))
	if err != nil {
		return nil, err
	}
	transList := make([]cfxtypes.Transaction, 0)
	if len(result) > 0 {
		for _, v := range result {
			block, err := wm.GetBlockByHash(v.String())
			if err != nil {
				//查找不到直接continue
				return nil, errors.New("can't find block" + v.String())
			}
			risk, err := wm.CfxClient.GetRawBlockConfirmationRisk(v)
			if err != nil {
				return nil, errors.New("can't find block risk" + v.String())
			}
			riskDecimal := decimal.NewFromBigInt(risk.ToInt(), 0)
			safe, _ := decimal.NewFromString("115792089237316195423570985008687907853269984665640564039457584007913129639936")
			safe = safe.Sub(decimal.NewFromInt(1))

			if riskDecimal.Div(safe).LessThanOrEqual(decimal.NewFromInt(1).Shift(-8)) {
				if len(block.Transactions) > 0 {
					for _, t := range block.Transactions {
						t.BlockHash = &block.Hash
						transList = append(transList, t)
					}
				}
			}

		}
	}
	return transList, nil
}

func (wm *WalletManager) GetBlockHashesByNum(blockNum uint64) (*openwallet.BlockHeader, []string, error) {

	result, err := wm.CfxClient.GetBlocksByEpoch(cfxtypes.NewEpochNumber(cfxtypes.NewBigInt(blockNum)))
	if err != nil {
		return nil, nil, err
	}
	if len(result) > 0 {
		hashStr := make([]string, 0)
		pHashStr := make([]string, 0)
		pHash := make(map[string]string)
		for _, v := range result {
			hashStr = append(hashStr, v.String())
			block, err := wm.GetBlockByHash(v.String())
			if err != nil {
				//查找不到直接continue
				continue
			}
			pHash[block.ParentHash.String()] = block.ParentHash.String()

		}
		if len(pHash) == 0 {
			return nil, nil, errors.New("can't find any block by parent")
		}
		for _, v := range pHash {
			pHashStr = append(pHashStr, v)
		}

		sort.Strings(pHashStr)
		sort.Strings(hashStr)
		header := &openwallet.BlockHeader{
			Hash:              hex.EncodeToString(encodeKey(hashStr)),
			Previousblockhash: hex.EncodeToString(encodeKey(pHashStr)),
			Height:            blockNum,
		}
		return header, hashStr, nil
		//return hex.EncodeToString(encodeKey(result)), hashStr, nil
	}

	return nil, nil, errors.New("can't find any block")
}

func (wm *WalletManager) GetBlockByHash(hash string) (*cfxtypes.Block, error) {

	result, err := wm.CfxClient.GetBlockByHash(cfxtypes.Hash(hash))
	if err != nil {
		return nil, err
	}

	return result, nil

}
func (wm *WalletManager) RecoverUnscannedTransactions(unscannedTxs []*openwallet.UnscanRecord) ([]*BlockTransaction, error) {
	allTxs := make([]*BlockTransaction, 0, len(unscannedTxs))
	for _, unscanned := range unscannedTxs {
		tx, err := wm.GetTransactionByHash(unscanned.TxID)
		if err != nil {
			return nil, err
		}
		allTxs = append(allTxs, tx)
	}
	return allTxs, nil
}

// CFX20GetAddressBalance
func (wm *WalletManager) CFX20GetAddressBalance(address string, contractAddr string) (*big.Int, error) {

	//address = wm.CustomAddressDecodeFunc(address)
	//contractAddr = wm.CustomAddressDecodeFunc(contractAddr)
	//address = AppendOxToAddress(address)
	//contractAddr = AppendOxToAddress(contractAddr)

	from ,_  := cfxaddress.NewFromBase32(address)

	deployedAt,_ := cfxaddress.NewFromBase32(contractAddr)

	contract,_ := wm.CfxClient.GetContract([]byte(CRC20_ABI_JSON),&deployedAt)

	balance := &struct{ Balance *big.Int }{}

	err := contract.Call(nil, balance, "balanceOf", from.MustGetCommonAddress())
	if err != nil {
		return nil,err
	}

	return balance.Balance, nil

}

// GetAddrBalance
func (wm *WalletManager) GetAddrBalance(address string, sign string) (*big.Int, error) {
	address = wm.CustomAddressDecodeFunc(address)
	params := []interface{}{
		address,
		sign,
	}
	result, err := wm.WalletClient.Call("cfx_getBalance", params)
	if err != nil {
		return big.NewInt(0), err
	}

	balance, err := hexutil.DecodeBig(result.String())
	if err != nil {
		return big.NewInt(0), err
	}
	return balance, nil
}

// GetBlockNumber
func (wm *WalletManager) GetBlockNumber() (uint64, error) {
	params := []interface{}{
		"latest_confirmed",
	}

	result, err := wm.WalletClient.Call("cfx_epochNumber", params)
	if err != nil {
		return 0, err
	}
	return hexutil.DecodeUint64(result.String())
}

func (wm *WalletManager) GetTransactionFeeEstimated(from string, to string, value *big.Int, data []byte) (*txFeeInfo, error) {

	var (
		gasLimit *big.Int
		gasPrice *big.Int
		err      error
	)
	if wm.Config.FixGasLimit.Cmp(big.NewInt(0)) > 0 {
		//配置设置固定gasLimit
		gasLimit = wm.Config.FixGasLimit
	} else {
		//动态计算gas消耗

		gasLimit, err = wm.GetGasEstimated(from, to, value, data)
		if err != nil {
			return nil, err
		}
	}

	if wm.Config.FixGasPrice.Cmp(big.NewInt(0)) > 0 {
		//配置设置固定gasLimit
		gasPrice = wm.Config.FixGasPrice
	} else {
		//动态计算gasPrice
		gasPrice, err = wm.GetGasPrice()
		if err != nil {
			return nil, err
		}
		gasPrice.Add(gasPrice, wm.Config.OffsetsGasPrice)
	}

	//	fee := new(big.Int)
	//	fee.Mul(gasLimit, gasPrice)

	feeInfo := &txFeeInfo{
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		//		Fee:      fee,
	}

	feeInfo.CalcFee()
	return feeInfo, nil
}

// GetGasEstimated
func (wm *WalletManager) GetGasEstimated(from string, to string, value *big.Int, data []byte) (*big.Int, error) {
	//toAddr := ethcom.HexToAddress(to)
	callMsg := map[string]interface{}{
		"from": wm.CustomAddressDecodeFunc(from),
		"to":   wm.CustomAddressDecodeFunc(to),
	}

	if data != nil {
		callMsg["data"] = hexutil.Encode(data)
	}

	if value != nil {
		callMsg["value"] = hexutil.EncodeBig(value)
	}

	result, err := wm.WalletClient.Call("cfx_estimateGasAndCollateral", []interface{}{callMsg})
	if err != nil {
		return big.NewInt(0), err
	}
	gasLimitStr := result.Get("gasLimit").String()
	gasLimit, err := common.StringValueToBigInt(gasLimitStr, 16)
	if err != nil {
		return big.NewInt(0), fmt.Errorf("convert estimated gas[%v] format to bigint failed, err = %v\n", result.String(), err)
	}
	return gasLimit, nil
}

func (wm *WalletManager) GetGasPrice() (*big.Int, error) {

	result, err := wm.WalletClient.Call("cfx_gasPrice", []interface{}{})
	if err != nil {
		return big.NewInt(0), err
	}

	gasLimit, err := common.StringValueToBigInt(result.String(), 16)
	if err != nil {
		return big.NewInt(0), fmt.Errorf("convert estimated gas[%v] format to bigint failed, err = %v\n", result.String(), err)
	}
	return gasLimit, nil
}

func (wm *WalletManager) SetNetworkChainID() (uint64, error) {

	result, err := wm.WalletClient.Call("cfx_getStatus", nil)
	if err != nil {
		return 0, err
	}
	id, err := hexutil.DecodeUint64(result.Get("chainId").String())
	if err != nil {
		return 0, err
	}
	wm.Config.ChainID = id
	//wm.Log.Debugf("Network chainID: %d", wm.Config.ChainID)
	return id, nil
}

// EncodeABIParam 编码API调用参数
func (wm *WalletManager) EncodeABIParam(abiInstance abi.ABI, abiParam ...string) ([]byte, error) {

	var (
		args = make([]interface{}, 0)
	)

	if len(abiParam) == 0 {
		return nil, fmt.Errorf("abi param length is empty")
	}
	method := abiParam[0]
	//转化string参数为abi调用参数
	abiMethod, ok := abiInstance.Methods[method]
	if !ok {
		return nil, fmt.Errorf("abi method can not found")
	}
	abiArgs := abiParam[1:]
	if len(abiMethod.Inputs) != len(abiArgs) {
		return nil, fmt.Errorf("abi input arguments is: %d, except is : %d", len(abiArgs), len(abiMethod.Inputs))
	}
	for i, input := range abiMethod.Inputs {
		//var a interface{}
		a, err := convertStringParamToABIParam(input.Type, abiArgs[i])
		if err != nil {
			return nil, err
		}
		args = append(args, a)
	}

	return abiInstance.Pack(method, args...)
}

// DecodeABIResult 解码ABI结果
func (wm *WalletManager) DecodeABIResult(abiInstance abi.ABI, method string, dataHex string) (map[string]interface{}, string, error) {

	var (
		err        error
		resultJSON []byte
		result     = make(CallResult)
	)
	data, _ := hexutil.Decode(dataHex)
	if len(data) == 0 {
		return result, "", nil
	}

	err = abiInstance.UnpackIntoMap(result, method, data)
	if err != nil {
		return result, string(resultJSON), err
	}
	resultJSON, err = result.MarshalJSON()
	return result, string(resultJSON), err
}

// DecodeReceiptLogResult 解码回执日志结果
func (wm *WalletManager) DecodeReceiptLogResult(abiInstance abi.ABI, log types.Log) (map[string]interface{}, string, string, error) {

	var (
		err        error
		resultJSON []byte
		result     = make(CallResult)
		event      *abi.Event
	)

	bc := bind.NewBoundContract(ethcom.HexToAddress("0x0"), abiInstance, nil, nil, nil)
	//wm.Log.Debugf("log.txid: %s", log.TxHash.String())
	//wm.Log.Debugf("log.Topics[0]: %s", log.Topics[0].Hex())
	//for _, e := range abiInstance.Events {
	//	wm.Log.Debugf("event: %s, ID: %s", e.Name, e.ID().Hex())
	//}
	event, err = abiInstance.EventByID(log.Topics[0])
	if err != nil {
		return result, "", "", err
	}
	err = bc.UnpackLogIntoMap(result, event.Name, log)
	if err != nil {
		return result, "", "", err
	}
	resultJSON, err = result.MarshalJSON()
	return result, event.Name, string(resultJSON), err
}

func (wm *WalletManager) EthCall(callMsg CallMsg, sign string) (string, error) {
	param := map[string]interface{}{
		"from":  callMsg.From.String(),
		"to":    callMsg.To.String(),
		"value": hexutil.EncodeBig(callMsg.Value),
		"data":  hexutil.Encode(callMsg.Data),
	}
	result, err := wm.WalletClient.Call("cfx_call", []interface{}{param, sign})
	if err != nil {
		return "", err
	}
	return result.String(), nil
}

// SendRawTransaction
func (wm *WalletManager) SendRawTransaction(signedTx string) (string, error) {
	params := []interface{}{
		signedTx,
	}

	result, err := wm.WalletClient.Call("cfx_sendRawTransaction", params)
	if err != nil {
		return "", err
	}

	return result.String(), nil
}

// IsContract 是否合约
func (wm *WalletManager) IsContract(address string) (bool, error) {
	params := []interface{}{
		wm.CustomAddressDecodeFunc(address),
		"latest",
	}

	result, err := wm.WalletClient.Call("cfx_getCode", params)
	if err != nil {
		return false, err
	}

	if result.String() == "0x" {
		return false, nil
	} else {
		return true, nil
	}

}

// GetAddressNonce
func (wm *WalletManager) GetAddressNonce(wrapper openwallet.WalletDAI, address string) uint64 {
	var (
		key           = wm.Symbol() + "-nonce"
		nonce         uint64
		nonce_db      interface{}
		nonce_onchain uint64
		err           error
	)

	//NonceComputeMode = 0时，使用外部系统的自增值
	if wm.Config.NonceComputeMode == 0 {
		//获取db记录的nonce并确认nonce值
		nonce_db, _ = wrapper.GetAddressExtParam(address, key)

		//判断nonce_db是否为空,为空则说明当前nonce是0
		if nonce_db == nil {
			nonce = 0
		} else {
			nonce = common.NewString(nonce_db).UInt64()
		}
	}

	nonce_onchain, err = wm.GetTransactionCount(address)
	if err != nil {
		return nonce
	}

	//如果本地nonce_db > 链上nonce,采用本地nonce,否则采用链上nonce
	if nonce > nonce_onchain {
		//wm.Log.Debugf("%s nonce_db=%v > nonce_chain=%v,Use nonce_db...", address, nonce_db, nonce_onchain)
	} else {
		nonce = nonce_onchain
		//wm.Log.Debugf("%s nonce_db=%v <= nonce_chain=%v,Use nonce_chain...", address, nonce_db, nonce_onchain)
	}

	//wm.Log.Debugf("nonce: %v", nonce)

	return nonce
}

// UpdateAddressNonce
func (wm *WalletManager) UpdateAddressNonce(wrapper openwallet.WalletDAI, address string, nonce uint64) {
	key := wm.Symbol() + "-nonce"
	err := wrapper.SetAddressExtParam(address, key, nonce)
	if err != nil {
		wm.Log.Errorf("WalletDAI SetAddressExtParam failed, err: %v", err)
	}
}

func AppendOxToAddress(addr string) string {
	if strings.Index(addr, "0x") == -1 {
		return "0x" + addr
	}
	return addr
}

func removeOxFromHex(value string) string {
	result := value
	if strings.Index(value, "0x") != -1 {
		result = common.Substr(value, 2, len(value))
	}
	return result
}

// convertStringParamToABIParam string参数转为ABI参数
func convertStringParamToABIParam(inputType abi.Type, abiArg string) (interface{}, error) {
	var (
		err error
		a   interface{}
	)

	switch inputType.T {
	case abi.BoolTy:
		a = common.NewString(abiArg).Bool()
	case abi.UintTy, abi.IntTy:
		a, err = convertParamToNum(abiArg, inputType)
	case abi.AddressTy:
		a = ethcom.HexToAddress(AppendOxToAddress(abiArg))
	case abi.FixedBytesTy, abi.BytesTy, abi.HashTy:
		slice, decodeErr := hexutil.Decode(AppendOxToAddress(abiArg))
		if decodeErr != nil {
			slice = owcrypt.Hash([]byte(abiArg), 0, owcrypt.HASH_ALG_KECCAK256)
			//return nil, fmt.Errorf("abi input hex string can not convert byte, err: %v", decodeErr)
		}
		var fixBytes [32]byte
		copy(fixBytes[:], slice)
		a = fixBytes
	case abi.StringTy:
		a = abiArg
	case abi.ArrayTy, abi.SliceTy:
		subArgs := strings.Split(abiArg, ",")
		a, err = convertArrayParamToABIParam(*inputType.Elem, subArgs)
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

//convertArrayParamToABIParam 数组参数转化
func convertArrayParamToABIParam(inputType abi.Type, subArgs []string) (interface{}, error) {
	var (
		err error
		a   interface{}
	)

	switch inputType.T {
	case abi.BoolTy:
		arr := make([]bool, 0)
		for _, subArg := range subArgs {
			elem, subErr := convertStringParamToABIParam(inputType, subArg)
			if subErr != nil {
				err = subErr
				break
			}
			arr = append(arr, elem.(bool))
		}
		a = arr
	case abi.UintTy:
		arr := make([]uint, 0)
		for _, subArg := range subArgs {
			elem, subErr := convertStringParamToABIParam(inputType, subArg)
			if subErr != nil {
				err = subErr
				break
			}
			arr = append(arr, elem.(uint))
		}
		a = arr
	case abi.IntTy:
		arr := make([]int, 0)
		for _, subArg := range subArgs {
			elem, subErr := convertStringParamToABIParam(inputType, subArg)
			if subErr != nil {
				err = subErr
				break
			}
			arr = append(arr, elem.(int))
		}
		a = arr
	case abi.AddressTy:
		arr := make([]ethcom.Address, 0)
		for _, subArg := range subArgs {
			elem, subErr := convertStringParamToABIParam(inputType, subArg)
			if subErr != nil {
				err = subErr
				break
			}
			arr = append(arr, elem.(ethcom.Address))
		}
		a = arr
	case abi.FixedBytesTy, abi.BytesTy, abi.HashTy:
		arr := make([][32]byte, 0)
		for _, subArg := range subArgs {
			elem, subErr := convertStringParamToABIParam(inputType, subArg)
			if subErr != nil {
				err = subErr
				break
			}
			arr = append(arr, elem.([32]byte))
		}
		a = arr
	case abi.StringTy:
		arr := make([]string, 0)
		for _, subArg := range subArgs {
			elem, subErr := convertStringParamToABIParam(inputType, subArg)
			if subErr != nil {
				err = subErr
				break
			}
			arr = append(arr, elem.(string))
		}
		a = arr
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func convertParamToNum(param string, abiType abi.Type) (interface{}, error) {
	var (
		base int
		bInt *big.Int
		err  error
	)
	if strings.HasPrefix(param, "0x") {
		base = 16
	} else {
		base = 10
	}
	bInt, err = common.StringValueToBigInt(param, base)
	if err != nil {
		return nil, err
	}
	//
	//switch abiType.TupleType {
	//case reflect.Uint:
	//	return uint(bInt.Uint64()), nil
	//case reflect.Uint8:
	//	return uint8(bInt.Uint64()), nil
	//case reflect.Uint16:
	//	return uint16(bInt.Uint64()), nil
	//case reflect.Uint32:
	//	return uint32(bInt.Uint64()), nil
	//case reflect.Uint64:
	//	return uint64(bInt.Uint64()), nil
	//case reflect.Int:
	//	return int(bInt.Int64()), nil
	//case reflect.Int8:
	//	return int8(bInt.Int64()), nil
	//case reflect.Int16:
	//	return int16(bInt.Int64()), nil
	//case reflect.Int32:
	//	return int32(bInt.Int64()), nil
	//case reflect.Int64:
	//	return int64(bInt.Int64()), nil
	//case reflect.Ptr:
		return bInt, nil
	//default:
	//	return nil, fmt.Errorf("abi input arguments: %v is invaild integer type", param)
	//}
}

func CustomAddressEncode(address string) string {
	return address
}
func CustomAddressDecode(address string) string {
	return address
}
