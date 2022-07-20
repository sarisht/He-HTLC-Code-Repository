package hehtlc

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSpendHeHTLCDepositAlice(t *testing.T) {
	params := GenTestParams()

	depositScript, depositAddr := BuildDepositContract(&params)
	fmt.Println("witness script (asm):", func() string {
		s, _ := txscript.DisasmString(depositScript)
		return s
	}())
	fmt.Println("witness script (hex):", hex.EncodeToString(depositScript))
	fmt.Println("P2WSH Deposit address:", depositAddr)
	// fmt.Println("P2SH Collateral address:", BuildHeHTLCCollateralP2SHAddr())

	//
	// TEST 1: DEPOSIT SPENT by ALICE (to Alice and Bob) (Dep-A)
	// Success.
	// Testnet tx: https://www.blockchain.com/btc-testnet/tx/5dbb7c677b3177700a541ecc23604bbfdb5ddd5a463e924428ae096646214180
	//
	t.Run("test tx_vdep_alice", func(t *testing.T) {
		txvDepAlice := SpendHeHTLCDepositAlice(&params)
		fmt.Println("spend by Alice:", txvDepAlice)
		assert.Equal(t, txvDepAlice, params.expectedAliceTx)
	})

	t.Run("test tx_vdep_Bob", func(t *testing.T) {
		txvdepBob := SpendHeHTLCDepositBob(&params)
		fmt.Println("spend tx by Bob", txvdepBob)
	})
}
