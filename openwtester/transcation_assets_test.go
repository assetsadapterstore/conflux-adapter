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

package openwtester

import (
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openw"
	"github.com/blocktree/openwallet/v2/openwallet"
	"testing"
)

func testGetAssetsAccountBalance(tm *openw.WalletManager, walletID, accountID string) {
	balance, err := tm.GetAssetsAccountBalance(testApp, walletID, accountID)
	if err != nil {
		log.Error("GetAssetsAccountBalance failed, unexpected error:", err)
		return
	}
	log.Info("balance:", balance)
}

func testGetAssetsAccountTokenBalance(tm *openw.WalletManager, walletID, accountID string, contract openwallet.SmartContract) {
	balance, err := tm.GetAssetsAccountTokenBalance(testApp, walletID, accountID, contract)
	if err != nil {
		log.Error("GetAssetsAccountTokenBalance failed, unexpected error:", err)
		return
	}
	log.Info("token balance:", balance.Balance)
}

func testCreateTransactionStep(tm *openw.WalletManager, walletID, accountID, to, amount, feeRate string, contract *openwallet.SmartContract, extParam map[string]interface{}) (*openwallet.RawTransaction, error) {

	//err := tm.RefreshAssetsAccountBalance(testApp, accountID)
	//if err != nil {
	//	log.Error("RefreshAssetsAccountBalance failed, unexpected error:", err)
	//	return nil, err
	//}

	rawTx, err := tm.CreateTransaction(testApp, walletID, accountID, amount, to, feeRate, "", contract, extParam)

	if err != nil {
		log.Error("CreateTransaction failed, unexpected error:", err)
		return nil, err
	}

	return rawTx, nil
}

func testCreateSummaryTransactionStep(
	tm *openw.WalletManager,
	walletID, accountID, summaryAddress, minTransfer, retainedBalance, feeRate string,
	start, limit int,
	contract *openwallet.SmartContract,
	feeSupportAccount *openwallet.FeesSupportAccount) ([]*openwallet.RawTransactionWithError, error) {

	rawTxArray, err := tm.CreateSummaryRawTransactionWithError(testApp, walletID, accountID, summaryAddress, minTransfer,
		retainedBalance, feeRate, start, limit, contract, feeSupportAccount)

	if err != nil {
		log.Error("CreateSummaryTransaction failed, unexpected error:", err)
		return nil, err
	}

	return rawTxArray, nil
}

func testSignTransactionStep(tm *openw.WalletManager, rawTx *openwallet.RawTransaction) (*openwallet.RawTransaction, error) {

	_, err := tm.SignTransaction(testApp, rawTx.Account.WalletID, rawTx.Account.AccountID, "12345678", rawTx)
	if err != nil {
		log.Error("SignTransaction failed, unexpected error:", err)
		return nil, err
	}

	log.Infof("rawTx: %+v", rawTx)
	return rawTx, nil
}

func testVerifyTransactionStep(tm *openw.WalletManager, rawTx *openwallet.RawTransaction) (*openwallet.RawTransaction, error) {

	//log.Info("rawTx.Signatures:", rawTx.Signatures)

	_, err := tm.VerifyTransaction(testApp, rawTx.Account.WalletID, rawTx.Account.AccountID, rawTx)
	if err != nil {
		log.Error("VerifyTransaction failed, unexpected error:", err)
		return nil, err
	}

	log.Infof("rawTx: %+v", rawTx)
	return rawTx, nil
}

func testSubmitTransactionStep(tm *openw.WalletManager, rawTx *openwallet.RawTransaction) (*openwallet.RawTransaction, error) {

	tx, err := tm.SubmitTransaction(testApp, rawTx.Account.WalletID, rawTx.Account.AccountID, rawTx)
	if err != nil {
		log.Error("SubmitTransaction failed, unexpected error:", err)
		return nil, err
	}

	log.Std.Info("tx: %+v", tx)
	log.Info("wxID:", tx.WxID)
	log.Info("txID:", rawTx.TxID)

	return rawTx, nil
}

func TestTransfer_CFX(t *testing.T) {

	addrs := []string{
		"cfx:aapmm76jgn4tc96h45kgtsuytnpzcne1s2xjb2djjn",
		//"cfx:aan7kmh0pkmvmmsezjfnc7c1n0atya1v5ypgmx36r2",
		//"cfx:aam2ja62jny28v59w7k715e57643j287sjdm33f5ez",
		//"cfx:aan1wtmwdpr2tkzjn6wr6r2sw7h67mr9sa3rmnm58r",
		//"cfx:aajpjd796x2vae1pvfmwk6tj38mj1vbv0pvejapmrh",
		//"cfx:aap3a7jd09w7fd3dk2003thw9fh6cpgmcurcrktupa",
		//"cfx:aat3ubbh4069rknr6x5xj7203k4rkgmnxan6m1zkte",
		//"cfx:aasza6y09fz0x4m3fst7ns3ftyzy1wu7xu0zd3fmxz",
		//"cfx:aatwet2956zpy02vt3kgeza94yue0fa1netp73gvjv",
		//"cfx:aan3r4m0tbp60pdbupm6bpcs4bup0g9wfy1hsntu89",
		//"cfx:aambhupzaa7rstuv04trwrkdjvdasr7ynyzbh099td",
		//"cfx:aak5y9js8ey7at6x1y8t9erh83903e6r4aur5hwxwn",
		//"cfx:aakrvatb36kjpg5yj0bu04086c3cwanccyuggrxx7s",
		//"cfx:aasxfn4jhmv91xn8khas8azu50dx02uvp6y6uegnex",
	}

	tm := testInitWalletManager()

	walletID := "W8BuKjHbeqRDj2wKHZLSyUXarg3fKhQ5Gd"
	accountID := "GpyZC7ZdfjYCRCVw9itgn1CGwR7rLFkXaz8TaV2zMeCu"




	testGetAssetsAccountBalance(tm, walletID, accountID)

	for _, to := range addrs {
		rawTx, err := testCreateTransactionStep(tm, walletID, accountID, to, "10", "", nil, nil)
		if err != nil {
			return
		}

		log.Std.Info("rawTx: %+v", rawTx)

		_, err = testSignTransactionStep(tm, rawTx)
		if err != nil {
			return
		}

		_, err = testVerifyTransactionStep(tm, rawTx)
		if err != nil {
			return
		}

		_, err = testSubmitTransactionStep(tm, rawTx)
		if err != nil {
			return
		}

	}
}

func TestTransfer_CRC20(t *testing.T) {

	addrs := []string{
		//"cfx:aajpjd796x2vae1pvfmwk6tj38mj1vbv0pvejapmrh",
		"cfx:aap3a7jd09w7fd3dk2003thw9fh6cpgmcurcrktupa",
		//"cfx:aat3ubbh4069rknr6x5xj7203k4rkgmnxan6m1zkte",
		//"cfx:aasza6y09fz0x4m3fst7ns3ftyzy1wu7xu0zd3fmxz",
		//"cfx:aatwet2956zpy02vt3kgeza94yue0fa1netp73gvjv",
		//"cfx:aan3r4m0tbp60pdbupm6bpcs4bup0g9wfy1hsntu89",
		//"cfx:aambhupzaa7rstuv04trwrkdjvdasr7ynyzbh099td",
		//"cfx:aak5y9js8ey7at6x1y8t9erh83903e6r4aur5hwxwn",
		//"cfx:aakrvatb36kjpg5yj0bu04086c3cwanccyuggrxx7s",
		//"cfx:aasxfn4jhmv91xn8khas8azu50dx02uvp6y6uegnex",
	}

	tm := testInitWalletManager()
	walletID := "W8BuKjHbeqRDj2wKHZLSyUXarg3fKhQ5Gd"
	accountID := "GpyZC7ZdfjYCRCVw9itgn1CGwR7rLFkXaz8TaV2zMeCu"

	//walletID := "W8BuKjHbeqRDj2wKHZLSyUXarg3fKhQ5Gd"
	//accountID := "4AXveixifVBC7BP7o1TZQ4gfM55W4sjaXcHbxKKHLfnn"
	contract := openwallet.SmartContract{
		Address:  "cfx:acfkgzsyk8ypsk28yvn3rd4sebhsn43b1pmban80bg",
		Symbol:   "CFX",
		Name:     "BLOCKLINK",
		Token:    "BT",
		Decimals: 18,
	}

	testGetAssetsAccountBalance(tm, walletID, accountID)

	testGetAssetsAccountTokenBalance(tm, walletID, accountID, contract)

	for _, to := range addrs {
		rawTx, err := testCreateTransactionStep(tm, walletID, accountID, to, "0.01", "", &contract, nil)
		if err != nil {
			return
		}

		log.Std.Info("rawTx: %+v", rawTx)

		_, err = testSignTransactionStep(tm, rawTx)
		if err != nil {
			return
		}

		_, err = testVerifyTransactionStep(tm, rawTx)
		if err != nil {
			return
		}

		_, err = testSubmitTransactionStep(tm, rawTx)
		if err != nil {
			return
		}

	}

}

func TestSummary_CFX(t *testing.T) {
	tm := testInitWalletManager()
	walletID := "W8BuKjHbeqRDj2wKHZLSyUXarg3fKhQ5Gd"
	accountID := "4AXveixifVBC7BP7o1TZQ4gfM55W4sjaXcHbxKKHLfnn"
	summaryAddress := "cfx:aaks4vj20ut9uru51a1pdvjebmamsb3ycupzag834m"

	testGetAssetsAccountBalance(tm, walletID, accountID)

	rawTxArray, err := testCreateSummaryTransactionStep(tm, walletID, accountID,
		summaryAddress, "", "", "",
		0, 100, nil, nil)
	if err != nil {
		log.Errorf("CreateSummaryTransaction failed, unexpected error: %v", err)
		return
	}

	//执行汇总交易
	for _, rawTxWithErr := range rawTxArray {

		if rawTxWithErr.Error != nil {
			log.Error(rawTxWithErr.Error.Error())
			continue
		}

		_, err = testSignTransactionStep(tm, rawTxWithErr.RawTx)
		if err != nil {
			return
		}

		_, err = testVerifyTransactionStep(tm, rawTxWithErr.RawTx)
		if err != nil {
			return
		}

		_, err = testSubmitTransactionStep(tm, rawTxWithErr.RawTx)
		if err != nil {
			return
		}
	}

}


func TestSummary_CRC20(t *testing.T) {
	tm := testInitWalletManager()
	walletID := "W8BuKjHbeqRDj2wKHZLSyUXarg3fKhQ5Gd"
	accountID := "4AXveixifVBC7BP7o1TZQ4gfM55W4sjaXcHbxKKHLfnn"
	summaryAddress := "cfx:aaks4vj20ut9uru51a1pdvjebmamsb3ycupzag834m"

	feesSupport := openwallet.FeesSupportAccount{
		AccountID: "7v7m8BfbZiCEuwFPerYjHdKM9J4xfNbpwUrKyN1ZFwN4",
		FixSupportAmount: "0.5",
		FeesSupportScale: "1.3",
	}

	contract := openwallet.SmartContract{
		Address:  "cfx:acfkgzsyk8ypsk28yvn3rd4sebhsn43b1pmban80bg",
		Symbol:   "CFX",
		Name:     "BLOCKLINK",
		Token:    "BT",
		Decimals: 18,
	}


	testGetAssetsAccountBalance(tm, walletID, accountID)

	testGetAssetsAccountTokenBalance(tm, walletID, accountID, contract)

	rawTxArray, err := testCreateSummaryTransactionStep(tm, walletID, accountID,
		summaryAddress, "", "", "",
		0, 100, &contract, &feesSupport)
	if err != nil {
		log.Errorf("CreateSummaryTransaction failed, unexpected error: %v", err)
		return
	}

	//执行汇总交易
	for _, rawTxWithErr := range rawTxArray {

		if rawTxWithErr.Error != nil {
			log.Error(rawTxWithErr.Error.Error())
			continue
		}

		_, err = testSignTransactionStep(tm, rawTxWithErr.RawTx)
		if err != nil {
			return
		}

		_, err = testVerifyTransactionStep(tm, rawTxWithErr.RawTx)
		if err != nil {
			return
		}

		_, err = testSubmitTransactionStep(tm, rawTxWithErr.RawTx)
		if err != nil {
			return
		}
	}

}
