package hehtlc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSpendHeHTLCDepositAlice(t *testing.T) {
	params := GenTestParams()

	depositScript, depositAddr := BuildDepositContract(&params)
	fmt.Println("[Dep] witness script (asm):", func() string {
		s, _ := txscript.DisasmString(depositScript)
		return s
	}())
	fmt.Println("[Dep] witness script (hex):", hex.EncodeToString(depositScript))
	fmt.Println("[Dep] P2WSH Deposit address:", depositAddr)

	//
	// TEST 1: DEPOSIT SPENT by ALICE (to Alice and Bob) (Dep-A)
	// Success.
	// Testnet tx: https://www.blockchain.com/btc-testnet/tx/5dbb7c677b3177700a541ecc23604bbfdb5ddd5a463e924428ae096646214180
	//
	t.Run("test tx_vdep_alice", func(t *testing.T) {
		txvDepAlice := SpendHeHTLCDepositAlice(&params)
		fmt.Println("spend by Alice:", txvDepAlice)
		assert.Equal(t, txvDepAlice, params.expectedTxDepAlice)
	})

	//
	// TEST 2: DEPOSIT TRANSFERRED TO COLLATERAL ACCOUNT BY BOB (Dep-B)
	// Success.
	// Testnet tx: https://www.blockchain.com/btc-testnet/tx/e80fcfb0a1ce936fcb9b514f03d2d78d4c8f06a0657e3a9f54411dee636d1ce6
	//
	t.Run("test tx_vdep_Bob", func(t *testing.T) {
		txDepBob, err := SpendHeHTLCDepositBob(&params)
		assert.NoError(t, err)

		var signedTx bytes.Buffer
		err = txDepBob.Serialize(&signedTx)
		if err != nil {
			panic(err)
		}

		hexSignedTx := hex.EncodeToString(signedTx.Bytes())
		assert.Equal(t, params.expectedTxDepBob, hexSignedTx)

		fmt.Println("[Dep] spend tx by Bob", hexSignedTx)

		fmt.Println("non-malleable txid", txDepBob.TxHash())
	})

	//
	// TEST 3: COLLATERAL SPENT BY BOB (Col-B)
	// Success.
	// Testnet tx: https://www.blockchain.com/btc-testnet/tx/a3f2902a3e7d3bd81295fc020a2a211dbf00b428f7bc6e93c4cfc12f7a55a628
	//
	t.Run("test tx_vcol_Bob", func(t *testing.T) {
		txColBob, err := SpendHeHTLCCollateralBob(&params)
		assert.NoError(t, err)

		var tx bytes.Buffer
		err = txColBob.Serialize(&tx)
		assert.NoError(t, err)

		fmt.Println("spend collateral by Bob", hex.EncodeToString(tx.Bytes()))
		assert.Equal(t, params.expectedTxColBob, hex.EncodeToString(tx.Bytes()))
	})

	// TEST 4: COLLATERAL SPENT by MINER (Col-M)
	// Success.
	// Testnet tx: https://www.blockchain.com/btc-testnet/tx/78b7ec346dc7ef75295ba26d1705cb791da23a97ff1511e28321e2b62f5de689
	t.Run("test tx_vcol_Miner", func(t *testing.T) {
		txColMiner, err := SpendHeHTLCCollateralMiner(&params)
		assert.NoError(t, err)

		var tx bytes.Buffer
		err = txColMiner.Serialize(&tx)
		assert.NoError(t, err)

		fmt.Println("[Col] spent by Miner", hex.EncodeToString(tx.Bytes()))
		assert.Equal(t, params.expectedTxColMiner, hex.EncodeToString(tx.Bytes()))
	})
}
