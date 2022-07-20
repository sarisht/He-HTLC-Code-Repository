package hehtlc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func P2WSHAddressFromWitnessScript(witnessScript []byte) btcutil.Address {
	// BIP-141: witness program is 0 (version) || SHA256 hash of witness script
	witnessScriptHash := sha256.Sum256(witnessScript)

	// if using Bitcoin main net then pass &chaincfg.MainNetParams as second argument
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessScriptHash[:], &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}

	return addr
}

func BuildDepositContract(params *Parameters) ([]byte, btcutil.Address) {
	// public keys extracted from wif.PrivKey
	pk1 := params.AlicePrivateKey.PrivKey.PubKey().SerializeCompressed()
	pk2 := params.BobPrivateKey.PrivKey.PubKey().SerializeCompressed()

	hash_prea := btcutil.Hash160(params.preA)
	hash_preb := btcutil.Hash160(params.preB)

	builder := txscript.NewScriptBuilder()

	// corresponding sigscript
	// preA || sigA || sigB, or
	// preB || OF_1 (dummy pre image) || sigA || sigB
	builder.AddOp(txscript.OP_2)
	builder.AddData(pk1).AddData(pk2)
	builder.AddOp(txscript.OP_2)
	builder.AddOp(txscript.OP_CHECKMULTISIGVERIFY)

	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(hash_prea)
	builder.AddOp(txscript.OP_EQUAL)

	builder.AddOp(txscript.OP_IF)   // if Alice provides pre_a, the script ends here
	builder.AddOp(txscript.OP_TRUE) // push the final true value

	builder.AddOp(txscript.OP_ELSE) // else, check Bob's input
	builder.AddInt64(params.T)      // Bob can spend after T block (relative)
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP) // drop T from stack

	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(hash_preb)
	builder.AddOp(txscript.OP_EQUAL)

	builder.AddOp(txscript.OP_ENDIF)

	witnessScript, err := builder.Script()
	if err != nil {
		panic(err)
	}

	return witnessScript, P2WSHAddressFromWitnessScript(witnessScript)
}

func BuildCollateralContract(params *Parameters) ([]byte, btcutil.Address) {
	pk1, pk2 := params.GetAliceBobPks()

	hashPreA := btcutil.Hash160(params.preA)
	hashPreB := btcutil.Hash160(params.preB)

	builder := txscript.NewScriptBuilder()

	// corresponding sigscript
	// t >= l || sigA || sigB, or
	// preB || preA || sigA || sigB
	builder.AddOp(txscript.OP_2)
	builder.AddData(pk1).AddData(pk2)
	builder.AddOp(txscript.OP_2)
	builder.AddOp(txscript.OP_CHECKMULTISIGVERIFY)

	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(hashPreA)
	builder.AddOp(txscript.OP_EQUAL)

	builder.AddOp(txscript.OP_IF) // if Alice provides pre_a, the script ends here
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(hashPreB)
	builder.AddOp(txscript.OP_EQUAL)

	builder.AddOp(txscript.OP_ELSE) // else, check Bob's input
	builder.AddInt64(params.ell)
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP) // drop ell from stack
	builder.AddOp(txscript.OP_TRUE)
	builder.AddOp(txscript.OP_ENDIF)

	witnessScript, err := builder.Script()
	if err != nil {
		panic(err)
	}

	witnessScriptHash := sha256.Sum256(witnessScript)
	fmt.Println("[Col] witness script", hex.EncodeToString(witnessScript[:]))
	fmt.Println("[Col] witness script hash", hex.EncodeToString(witnessScriptHash[:]))

	return witnessScript, P2WSHAddressFromWitnessScript(witnessScript)
}

func SpendHeHTLCDepositAlice(params *Parameters) string {
	// output address
	destinationAddrByteAlice, err := txscript.PayToAddrScript(params.GetAliceAddressOrPanic())
	if err != nil {
		panic(err)
	}
	destinationAddrByteBob, err := txscript.PayToAddrScript(params.GetBobAddressOrPanic())
	if err != nil {
		panic(err)
	}

	redeemTxOutAlice := wire.NewTxOut(int64(params.vdep), destinationAddrByteAlice)
	redeemTxOutBob := wire.NewTxOut(int64(params.vcol), destinationAddrByteBob)

	witnessScript, _ := BuildDepositContract(params)

	// get the UTXO
	txIn := wire.NewTxIn(params.GetDepositUTXO4Alice(), nil, nil)

	// a new tx
	tvDepAlice := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
	tvDepAlice.AddTxIn(txIn)
	tvDepAlice.AddTxOut(redeemTxOutAlice)
	tvDepAlice.AddTxOut(redeemTxOutBob)

	// BIP-143 signs the amount of UTXO too
	amount := params.depositUTXOForAlice.amount
	prevOutput := txscript.NewCannedPrevOutputFetcher(nil, amount)

	sigHash := txscript.NewTxSigHashes(tvDepAlice, prevOutput)

	sigA, err := txscript.RawTxInWitnessSignature(tvDepAlice, sigHash, 0, amount, witnessScript, txscript.SigHashAll, params.AlicePrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	sigB, err := txscript.RawTxInWitnessSignature(tvDepAlice, sigHash, 0, amount, witnessScript, txscript.SigHashAll, params.BobPrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	//!!! everything below is NOT covered by signatures.
	// See https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

	// witness stack
	tvDepAlice.TxIn[0].Witness = wire.TxWitness{
		params.preA,
		[]byte{}, // dummy value for MULTISIG must be empty per https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
		sigA,
		sigB,
		witnessScript,
	}

	var signedTx bytes.Buffer
	err = tvDepAlice.Serialize(&signedTx)
	if err != nil {
		panic(err)
	}

	hexSignedTx := hex.EncodeToString(signedTx.Bytes())

	return hexSignedTx
}

func SpendHeHTLCDepositBob(params *Parameters) (*wire.MsgTx, error) {
	depositUTXO := params.GetDepositUTXOForBob()
	txIn := wire.NewTxIn(depositUTXO, nil, nil)

	depPkScript, _ := BuildDepositContract(params)

	// a new tx
	txDepBob := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
	txDepBob.AddTxIn(txIn)

	// witness script for the collateral
	_, colP2WSHAddress := BuildCollateralContract(params)
	colPkScript, err := txscript.PayToAddrScript(colP2WSHAddress)
	if err != nil {
		return nil, err
	}

	redeemTxOutCol := wire.NewTxOut(
		params.vdep+params.vcol+params.fee,
		colPkScript)

	txDepBob.AddTxOut(redeemTxOutCol)

	// activate OP_CSV
	// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
	// https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
	txDepBob.TxIn[0].Sequence = uint32(params.T)

	// sign with BIP-143 amount of UTXO
	amount := params.depositUTXOForBob.amount
	prevOutput := txscript.NewCannedPrevOutputFetcher(nil, amount)

	sigHash := txscript.NewTxSigHashes(txDepBob, prevOutput)

	sigA, err := txscript.RawTxInWitnessSignature(txDepBob, sigHash, 0, amount, depPkScript, txscript.SigHashAll, params.AlicePrivateKey.PrivKey)
	if err != nil {
		return nil, err
	}

	sigB, err := txscript.RawTxInWitnessSignature(txDepBob, sigHash, 0, amount, depPkScript, txscript.SigHashAll, params.BobPrivateKey.PrivKey)
	if err != nil {
		return nil, err
	}

	//!!! everything below is NOT covered by signatures.
	// See https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

	// witness stack
	txDepBob.TxIn[0].Witness = wire.TxWitness{
		params.preB,
		[]byte{0x00}, // add dummy value to be consumed by first OP_HASH160
		[]byte{},     // dummy value for MULTISIG must be empty per https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
		sigA,
		sigB,
		depPkScript,
	}

	return txDepBob, nil
}

func SpendHeHTLCCollateralBob(params *Parameters) (*wire.MsgTx, error) {
	redeemScript, _ := BuildCollateralContract(params)

	destinationAddrByteBob, err := txscript.PayToAddrScript(params.GetBobAddressOrPanic())
	if err != nil {
		return nil, err
	}

	// vdep + vcol to Bob
	redeemTxOutBob := wire.NewTxOut(params.vcol+params.vdep, destinationAddrByteBob)

	// txid & utxo index
	txIn := wire.NewTxIn(params.GetCollateralUTXOForBob(), nil, nil)

	// a new tx
	redeemTx := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
	redeemTx.AddTxIn(txIn)
	redeemTx.AddTxOut(redeemTxOutBob)

	// activate OP_CSV
	// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
	// https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
	redeemTx.TxIn[0].Sequence = uint32(params.ell)

	// signing the tx
	amount := params.collateralUTXOForBob.amount
	prevOutput := txscript.NewCannedPrevOutputFetcher(nil, amount)

	sigHash := txscript.NewTxSigHashes(redeemTx, prevOutput)

	sigA, err := txscript.RawTxInWitnessSignature(redeemTx, sigHash, 0, amount, redeemScript, txscript.SigHashAll, params.AlicePrivateKey.PrivKey)
	if err != nil {
		return nil, err
	}

	sigB, err := txscript.RawTxInWitnessSignature(redeemTx, sigHash, 0, amount, redeemScript, txscript.SigHashAll, params.BobPrivateKey.PrivKey)
	if err != nil {
		return nil, err
	}

	//!!! everything below is NOT covered by signatures.
	// See https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

	// witness stack
	redeemTx.TxIn[0].Witness = wire.TxWitness{
		[]byte{0x00}, // add dummy value to be consumed by first OP_HASH160
		[]byte{},     // dummy value for MULTISIG must be empty per https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
		sigA,
		sigB,
		redeemScript,
	}

	return redeemTx, nil
}

func SpendHeHTLCCollateralMiner(params *Parameters) (*wire.MsgTx, error) {
	// a new tx
	redeemTx := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)

	// UTXO
	txIn := wire.NewTxIn(params.GetCollateralUTXOForMiner(), nil, nil)
	redeemTx.AddTxIn(txIn)

	// create a single output with vdep provably unspendable
	// the rest (vcol) will become part of the transaction fee
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_RETURN)
	unspendable, err := builder.Script()
	if err != nil {
		return nil, err
	}

	// must hide OP_RETURN in a P2SH otherwise the transaction will be considered non-standard (too small)

	//calculate the hash160 of the redeem script
	redeemHash := btcutil.Hash160(unspendable)

	addr, err := btcutil.NewAddressScriptHashFromHash(redeemHash, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	redeemTxOutBurn := wire.NewTxOut(params.vdep, pkScript)

	redeemTx.AddTxOut(redeemTxOutBurn)

	// sign the tx
	amount := params.collateralUTXOForMiner.amount
	prevOutput := txscript.NewCannedPrevOutputFetcher(nil, amount)

	sigHash := txscript.NewTxSigHashes(redeemTx, prevOutput)

	colWitnessScript, _ := BuildCollateralContract(params)
	siga, err := txscript.RawTxInWitnessSignature(redeemTx, sigHash, 0, amount, colWitnessScript, txscript.SigHashAll, params.AlicePrivateKey.PrivKey)
	if err != nil {
		return nil, err
	}

	sigb, err := txscript.RawTxInWitnessSignature(redeemTx, sigHash, 0, amount, colWitnessScript, txscript.SigHashAll, params.BobPrivateKey.PrivKey)
	if err != nil {
		return nil, err
	}

	//!!! everything below is NOT covered by signatures.
	// See https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

	// witness stack
	redeemTx.TxIn[0].Witness = wire.TxWitness{
		params.preB,
		params.preA,
		[]byte{}, // dummy value for MULTISIG must be empty per https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
		siga,
		sigb,
		colWitnessScript,
	}

	return redeemTx, nil
}
