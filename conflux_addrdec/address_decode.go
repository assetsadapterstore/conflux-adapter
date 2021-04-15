package conflux_addrdec

import (
	"encoding/hex"
	"github.com/Conflux-Chain/go-conflux-sdk/types/cfxaddress"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/ethereum/go-ethereum/common"
	"strings"
)

var (
	Default = AddressDecoderV2{}
)

//AddressDecoderV2
type AddressDecoderV2 struct {
	*openwallet.AddressDecoderV2Base
}

//NewAddressDecoder 地址解析器
func NewAddressDecoderV2() *AddressDecoderV2 {
	decoder := AddressDecoderV2{}
	return &decoder
}

//AddressDecode 地址解析
func (dec *AddressDecoderV2) AddressDecode(addr string, opts ...interface{}) ([]byte, error) {

	expect := cfxaddress.MustNewFromBase32(addr)
	addr = strings.TrimPrefix(expect.GetHexAddress(), "0x")
	decodeAddr, err := hex.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	return decodeAddr, err

}

//AddressEncode 地址编码
func (dec *AddressDecoderV2) AddressEncode(hash []byte, opts ...interface{}) (string, error) {

	if len(hash) != 32 {
		//公钥hash处理
		publicKey := owcrypt.PointDecompress(hash, owcrypt.ECC_CURVE_SECP256K1)
		hash = owcrypt.Hash(publicKey[1:len(publicKey)], 0, owcrypt.HASH_ALG_KECCAK256)

	}

	//地址添加0x前缀
	address := "0x" + hex.EncodeToString(hash[12:])

	real := common.HexToAddress(address)
	real[0] = real[0]&0x1f | 0x10

	caddress,err := cfxaddress.New(real.Hex(),1029)
	if err != nil{
		return "",err
	}
	return caddress.MustGetBase32Address(), nil
}

// AddressVerify 地址校验
func (dec *AddressDecoderV2) AddressVerify(address string, opts ...interface{}) bool {
	if address == "" {
		return false
	}

	if strings.Index(address, "0x") != 0 {
		return false
	}

	addrByte, err := hex.DecodeString(address[2:])
	if err != nil {
		return false
	}

	if len(addrByte) != 20 {
		return false
	}

	return true
}
