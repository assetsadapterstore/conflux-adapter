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
	"encoding/json"
	"fmt"
	cfxtypes "github.com/Conflux-Chain/go-conflux-sdk/types"
	"github.com/Conflux-Chain/go-conflux-sdk/types/cfxaddress"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/common"
	"github.com/blocktree/openwallet/v2/hdkeystore"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcom "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/tidwall/gjson"
	"math/big"
	"reflect"
	"strings"
	"time"
)

const (
	CRC20_ABI_JSON = `[{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"constant":true,"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"PERMIT_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]`
)

var (
	CRC20_ABI, _ = abi.JSON(strings.NewReader(CRC20_ABI_JSON))
)

type EthBlock struct {
	BlockHeader
	Transactions []*BlockTransaction `json:"transactions"`
}

func (block *EthBlock) CreateOpenWalletBlockHeader() *openwallet.BlockHeader {
	header := &openwallet.BlockHeader{
		Hash:              block.BlockHash,
		Previousblockhash: block.PreviousHash,
		Height:            block.BlockHeight,
		Time:              uint64(time.Now().Unix()),
	}
	return header
}

type BlockArray struct {
	Height string `json:"height" storm:"id"`
	Hashes string `json:"hashes" storm:"hashes"`
}

//func(b *BlockArray) BlocksToStrArray() []string{
//hex.De
//}

type CRC20Token struct {
	Address  string `json:"address" storm:"id"`
	Symbol   string `json:"symbol" storm:"index"`
	Name     string `json:"name"`
	Decimals int    `json:"decimals"`
	balance  *big.Int
}

type EthEvent struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `josn:"data"`
	//BlockNumber string
	LogIndex string `json:"logIndex"`
	Removed  bool   `json:"removed"`
}

type TransactionReceipt struct {
	CFXReceipt *cfxtypes.TransactionReceipt
}

type TransferEvent struct {
	ContractAddress string
	TokenName       string
	TokenSymbol     string
	TokenDecimals   uint8
	TokenFrom       string
	TokenTo         string
	From            ethcom.Address
	To              ethcom.Address
	Value           *big.Int
}

func (receipt *TransactionReceipt) ParseTransferEvent() map[string][]*TransferEvent {
	var (
		transferEvents = make(map[string][]*TransferEvent)
		err            error
	)

	if receipt == nil {
		return transferEvents
	}

	bc := bind.NewBoundContract(ethcom.HexToAddress("0x0"), CRC20_ABI, nil, nil, nil)
	for _, log := range receipt.CFXReceipt.Logs {

		if len(log.Topics) != 3 {
			continue
		}

		topic := log.Topics[0].ToCommonHash()
		event, _ := CRC20_ABI.EventByID(*topic)
		if event == nil || event.Name != "Transfer" {
			continue
		}

		address := strings.ToLower(log.Address.MustGetBase32Address())

		topics := make([]ethcom.Hash, len(log.Topics))
		for i, v := range log.Topics {
			topics[i] = *v.ToCommonHash()
		}


		eLog := types.Log{}
		eLog.Topics = topics
		eLog.Data = []byte(log.Data)


		var transfer TransferEvent
		err = bc.UnpackLog(&transfer, "Transfer", eLog)
		if err != nil {
			continue
		}

		events := transferEvents[address]
		if events == nil {
			events = make([]*TransferEvent, 0)
		}
		transfer.ContractAddress = address
		cfxFrom,_ := cfxaddress.NewFromCommon(transfer.From,1029)
		cfxTo,_ := cfxaddress.NewFromCommon(transfer.To,1029)

		transfer.TokenFrom = strings.ToLower(cfxFrom.MustGetBase32Address())
		transfer.TokenTo = strings.ToLower(cfxTo.MustGetBase32Address())

		events = append(events, &transfer)
		transferEvents[address] = events
	}

	return transferEvents
}

type Address struct {
	Address      string `json:"address" storm:"id"`
	Account      string `json:"account" storm:"index"`
	HDPath       string `json:"hdpath"`
	Index        int
	PublicKey    string
	balance      *big.Int //string `json:"balance"`
	tokenBalance *big.Int
	TxCount      uint64
	CreatedAt    time.Time
}

func (this *Address) CalcPrivKey(masterKey *hdkeystore.HDKey) ([]byte, error) {
	childKey, _ := masterKey.DerivedKeyWithPath(this.HDPath, owcrypt.ECC_CURVE_SECP256K1)
	keyBytes, err := childKey.GetPrivateKeyBytes()
	if err != nil {
		log.Error("get private key bytes, err=", err)
		return nil, err
	}
	return keyBytes, nil
}

func (this *Address) CalcHexPrivKey(masterKey *hdkeystore.HDKey) (string, error) {
	prikey, err := this.CalcPrivKey(masterKey)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(prikey), nil
}

type BlockTransaction struct {
	Hash             string `json:"hash" storm:"id"`
	BlockNumber      string `json:"blockNumber" storm:"index"`
	BlockHash        string `json:"blockHash" storm:"index"`
	From             string `json:"from"`
	To               string `json:"to"`
	Gas              string `json:"gas"`
	GasPrice         string `json:"gasPrice"`
	Value            string `json:"value"`
	Data             string `json:"input"`
	TransactionIndex string `json:"transactionIndex"`
	Timestamp        string `json:"timestamp"`
	BlockHeight      uint64 //transaction scanning ???????????????????????????
	FilterFunc       openwallet.BlockScanTargetFuncV2
	Status           uint64
	receipt          *TransactionReceipt
	decimal          int32
}

func CreateBlockTransaction(transaction *cfxtypes.Transaction, decimal int32) *BlockTransaction {
	temp := &BlockTransaction{
		Hash:        transaction.Hash.String(),
		BlockHash:   transaction.BlockHash.String(),
		BlockNumber: transaction.EpochHeight.String(),
		Gas:         transaction.Gas.String(),
		GasPrice:    transaction.GasPrice.String(),
		Value:       transaction.Value.String(),
		decimal:     decimal,
		//TransactionIndex: transaction.TransactionIndex.String(),
	}

	temp.From = transaction.From.MustGetBase32Address()

	if transaction.To != nil {
		temp.To = transaction.To.MustGetBase32Address()
	}

	if transaction.Status != nil {
		if transaction.Status.String() == "0x0" {
			temp.Status = uint64(1)
		}
	}
	if transaction.TransactionIndex != nil {
		temp.TransactionIndex = transaction.TransactionIndex.String()
	}
	return temp
}

func CreateBlockTransactionList(transactions []cfxtypes.Transaction, decimal int32) []*BlockTransaction {
	blockTransactions := make([]*BlockTransaction, 0)
	if len(transactions) > 0 {
		for _, transaction := range transactions {
			temp := &BlockTransaction{
				Hash:        transaction.Hash.String(),
				BlockNumber: transaction.EpochHeight.String(),
				Gas:       transaction.Gas.String(),
				BlockHash: transaction.BlockHash.String(),
				GasPrice:  transaction.GasPrice.String(),
				Value:     transaction.Value.String(),
				decimal:   decimal,
			}

			temp.From = transaction.From.MustGetBase32Address()

			if transaction.To != nil {
				temp.To = transaction.To.MustGetBase32Address()
			}

			if transaction.Status != nil {
				if transaction.Status.String() == "0x0" {
					temp.Status = uint64(1)
				}
			}
			if transaction.TransactionIndex != nil {
				temp.TransactionIndex = transaction.TransactionIndex.String()
			}

			blockTransactions = append(blockTransactions, temp)

		}
	}

	return blockTransactions
}

func (this *BlockTransaction) GetAmountEthString() string {
	amount, _ := hexutil.DecodeBig(this.Value)
	amountVal := common.BigIntToDecimals(amount, this.decimal)
	return amountVal.String()
}

func (this *BlockTransaction) GetTxFeeEthString() string {
	gasPrice, _ := hexutil.DecodeBig(this.GasPrice)
	gas, _ := hexutil.DecodeBig(this.Gas)
	fee := big.NewInt(0)
	if this.Gas == ""{
		return fee.String()
	}
	fee.Mul(gasPrice, gas)
	feeprice := common.BigIntToDecimals(fee, this.decimal)
	return feeprice.String()
}

type BlockHeader struct {
	BlockNumber     string `json:"number" storm:"id"`
	BlockHash       string `json:"hash"`
	GasLimit        string `json:"gasLimit"`
	GasUsed         string `json:"gasUsed"`
	Miner           string `json:"miner"`
	Difficulty      string `json:"difficulty"`
	TotalDifficulty string `json:"totalDifficulty"`
	PreviousHash    string `json:"parentHash"`
	BlockHeight     uint64 //RecoverBlockHeader????????????????????????
}

type txFeeInfo struct {
	GasLimit *big.Int
	GasPrice *big.Int
	Fee      *big.Int
}

func (txFee *txFeeInfo) CalcFee() error {
	fee := new(big.Int)
	fee.Mul(txFee.GasLimit, txFee.GasPrice)
	txFee.Fee = fee
	return nil
}

//type CallMsg struct {
//	From     string `json:"from"`
//	To       string `json:"to"`
//	Data     string `json:"data"`
//	Value    string `json:"value"`
//	gas      string `json:"gas"`
//	gasPrice string `json:"gasPrice"`
//}

type CallMsg struct {
	To       ethcom.Address `json:"to"`
	From     ethcom.Address `json:"from"`
	Nonce    uint64         `json:"nonce"`
	Value    *big.Int       `json:"value"`
	GasLimit uint64         `json:"gasLimit"`
	Gas      uint64         `json:"gas"`
	GasPrice *big.Int       `json:"gasPrice"`
	Data     []byte         `json:"data"`
}

func (msg *CallMsg) UnmarshalJSON(data []byte) error {
	obj := gjson.ParseBytes(data)
	msg.From = ethcom.HexToAddress(obj.Get("from").String())
	msg.To = ethcom.HexToAddress(obj.Get("to").String())
	msg.Nonce, _ = hexutil.DecodeUint64(obj.Get("nonce").String())
	msg.Value, _ = hexutil.DecodeBig(obj.Get("value").String())
	msg.GasLimit, _ = hexutil.DecodeUint64(obj.Get("gasLimit").String())
	msg.Gas, _ = hexutil.DecodeUint64(obj.Get("gas").String())
	msg.GasPrice, _ = hexutil.DecodeBig(obj.Get("gasPrice").String())
	msg.Data, _ = hexutil.Decode(obj.Get("data").String())
	return nil
}

func (msg *CallMsg) MarshalJSON() ([]byte, error) {
	obj := map[string]interface{}{
		"from":     msg.From.String(),
		"to":       msg.To.String(),
		"nonce":    hexutil.EncodeUint64(msg.Nonce),
		"gasLimit": hexutil.EncodeUint64(msg.Nonce),
		"gas":      hexutil.EncodeUint64(msg.Nonce),
	}

	if msg.Value != nil {
		obj["value"] = hexutil.EncodeBig(msg.Value)
	}
	if msg.GasPrice != nil {
		obj["gasPrice"] = hexutil.EncodeBig(msg.GasPrice)
	}
	if msg.Data != nil {
		obj["data"] = hexutil.Encode(msg.Data)
	}
	return json.Marshal(obj)
}

type CallResult map[string]interface{}

func (r CallResult) MarshalJSON() ([]byte, error) {
	newR := make(map[string]interface{})
	for key, value := range r {
		val := reflect.ValueOf(value) //??????????????????????????????????????????
		if isByteArray(val.Type()) {
			newR[key] = toHex(value)
		} else {
			newR[key] = value
		}
	}
	return json.Marshal(newR)
}

func toHex(key interface{}) string {
	return fmt.Sprintf("0x%x", key)
}

func isByteArray(typ reflect.Type) bool {
	return (typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array) && isByte(typ.Elem())
}

func isByte(typ reflect.Type) bool {
	return typ.Kind() == reflect.Uint8
}
