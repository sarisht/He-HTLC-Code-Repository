package hehtlc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	Alice = iota
	Bob
)

func main() {
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
	// Testnet tx: https://www.blockchain.com/btc-testnet/tx/6dc135484d4327ae4208043db961f25231c457d02723b94dd44d64a9368e7365
	//
	txvDepAlice := SpendHeHTLCDepositAlice(&params)
	fmt.Println("spend by Alice:", txvDepAlice)
	if txvDepAlice != params.expectedAliceTx {
		panic("test for Alice failed")
	}

	// /*
	// 	TEST 2: DEPOSIT TRANSFERRED TO COLLATERAL ACCOUNT BY BOB (Dep-B)
	// 	Success.
	// 	Testnet tx: https://blockchair.com/bitcoin/testnet/transaction/062e046f6aab94f65351e55747e278c640dce28ba273c67343149ce4c5c26ca8
	// */
	// fmt.Println("spend by Bob:", SpendHeHTLCDepositBob())

	// /*
	// 	TEST 3: COLLATERAL REDEEMED BY BOB (Col-B)
	// 	Success.
	// 	Testnet tx: https://blockchair.com/bitcoin/testnet/transaction/fc52f6043c0c3b93234239c6617e7a4220e151a23a69668498b002fbfb15b607
	// */
	// fmt.Println("collateral spend by Bob:", SpendHeHTLCCollateralBob())

	// /*
	// 	TEST 4: COLLATERAL SPENT by MINER (Col-M)
	// 	Success.
	// 	Testnet tx: https://blockchair.com/bitcoin/testnet/transaction/7639937a8168431a6434099022cc3d2382bb875fe91cc861aba61750928f2fdf
	// */

	// fmt.Println("miner spends: ", SpendHeHTLCCollateralMiner())
}

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

	return witnessScript, P2WSHAddressFromWitnessScript(witnessScript)
}

func BuildBurnContract() []byte {

	builder := txscript.NewScriptBuilder()

	// corresponding sigscript
	// t >= l || sigA || sigB, or
	// preB || preA || sigA || sigB
	builder.AddOp(txscript.OP_RETURN)

	redeemScript, err := builder.Script()
	if err != nil {
		panic(err)
	}
	return redeemScript
}

func BuildHeHTLCBurnP2SHAddr() string {
	redeemScript := BuildBurnContract()

	// calculate the hash160 of the redeem script
	redeemHash := btcutil.Hash160(redeemScript)

	// if using Bitcoin main net then pass &chaincfg.MainNetParams as second argument
	addr, err := btcutil.NewAddressScriptHashFromHash(redeemHash, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}

	return addr.EncodeAddress()
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

	// sign with BIP-143 amount of UTXO
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

func SpendHeHTLCDepositBob(params *Parameters) string {
	depositUTXO := params.GetDepositUTXOForBob()
	txIn := wire.NewTxIn(depositUTXO, nil, nil)

	// a new tx
	redeemTx := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
	redeemTx.AddTxIn(txIn)

	// witness script
	witnessScript, colP2WSHAddress := BuildDepositContract(params)

	colPkScript, err := txscript.PayToAddrScript(colP2WSHAddress)
	if err != nil {
		panic(err)
	}

	redeemTxOutCol := wire.NewTxOut(
		params.vdep+params.vcol+params.fee,
		colPkScript)

	redeemTx.AddTxOut(redeemTxOutCol)

	// activate OP_CSV
	// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
	// https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
	redeemTx.TxIn[0].Sequence = uint32(params.T)

	// sign with BIP-143 amount of UTXO
	amount := params.depositUTXOForBob.amount
	prevOutput := txscript.NewCannedPrevOutputFetcher(nil, amount)

	sigHash := txscript.NewTxSigHashes(redeemTx, prevOutput)

	sigA, err := txscript.RawTxInWitnessSignature(redeemTx, sigHash, 0, amount, witnessScript, txscript.SigHashAll, params.AlicePrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	sigB, err := txscript.RawTxInWitnessSignature(redeemTx, sigHash, 0, amount, witnessScript, txscript.SigHashAll, params.BobPrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	//!!! everything below is NOT covered by signatures.
	// See https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

	// witness stack
	redeemTx.TxIn[0].Witness = wire.TxWitness{
		params.preB,
		[]byte{0x00}, // add dummy value to be consumed by first OP_HASH160
		[]byte{},     // dummy value for MULTISIG must be empty per https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
		sigA,
		sigB,
		witnessScript,
	}

	//signature := txscript.NewScriptBuilder()
	//signature.AddData(params.preB)
	//signature.AddOp(txscript.OP_0) // add dummy value to be consumed by first OP_HASH160
	//signature.AddOp(txscript.OP_0) // deal with the off-by-one error in CHECKMULTISIG https://learnmeabitcoin.com/technical/p2ms
	//signature.AddData(sigA)
	//signature.AddData(sigB)
	//signature.AddData(witnessScript)

	//signatureScript, err := signature.Script()
	//if err != nil {
	//	panic(err)
	//}
	//
	//redeemTx.TxIn[0].SignatureScript = signatureScript

	var signedTx bytes.Buffer
	err = redeemTx.Serialize(&signedTx)
	if err != nil {
		panic(err)
	}

	hexSignedTx := hex.EncodeToString(signedTx.Bytes())

	return hexSignedTx
}

func SpendHeHTLCCollateralBob() string {

	params := GenTestParams()

	redeemScript, _ := BuildCollateralContract(&params)

	decodedAddrBob, err := btcutil.DecodeAddress(params.Bob2Bech32Address, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}
	destinationAddrByteBob, err := txscript.PayToAddrScript(decodedAddrBob)
	if err != nil {
		panic(err)
	}
	redeemTxOutBob := wire.NewTxOut(int64(params.vcol)+int64(params.vdep), destinationAddrByteBob)

	// txid & utxo index
	utxoHash, err := chainhash.NewHashFromStr(params.collateralUTXOForBob.txid)
	if err != nil {
		panic(err)
	}
	outPoint := wire.NewOutPoint(utxoHash, params.collateralUTXOForBob.utxo)
	txIn := wire.NewTxIn(outPoint, nil, nil)

	// a new tx
	redeemTx := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
	redeemTx.AddTxIn(txIn)
	redeemTx.AddTxOut(redeemTxOutBob)

	// signing the tx
	fmt.Println("preA: ", hex.EncodeToString(params.preA))
	fmt.Println("preB: ", hex.EncodeToString(params.preB))

	// activate OP_CSV
	// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
	// https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
	redeemTx.TxIn[0].Sequence = uint32(params.ell)

	siga, err := txscript.RawTxInSignature(redeemTx, 0, redeemScript, txscript.SigHashAll, params.AlicePrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	sigb, err := txscript.RawTxInSignature(redeemTx, 0, redeemScript, txscript.SigHashAll, params.BobPrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	//!!! everything below is NOT covered by signatures.
	// See https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

	signature := txscript.NewScriptBuilder()

	signature.AddOp(txscript.OP_0) // // add dummy value to be consumed by first OP_HASH160

	signature.AddOp(txscript.OP_0) // deal with the off-by-one error in CHECKMULTISIG https://learnmeabitcoin.com/technical/p2ms
	signature.AddData(siga)
	signature.AddData(sigb)
	signature.AddData(redeemScript)

	signatureScript, err := signature.Script()
	if err != nil {
		panic(err)
	}

	redeemTx.TxIn[0].SignatureScript = signatureScript

	var signedTx bytes.Buffer
	redeemTx.Serialize(&signedTx)

	hexSignedTx := hex.EncodeToString(signedTx.Bytes())

	return hexSignedTx
}

func SpendHeHTLCCollateralMiner() string {

	params := GenTestParams()

	redeemScript, _ := BuildCollateralContract(&params)

	burnAddr := BuildHeHTLCBurnP2SHAddr()

	decodedAddrBurn, err := btcutil.DecodeAddress(string(burnAddr), &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}
	destinationAddrByteBurn, err := txscript.PayToAddrScript(decodedAddrBurn)
	if err != nil {
		panic(err)
	}
	redeemTxOutBurn := wire.NewTxOut(int64(params.vdep), destinationAddrByteBurn)

	// txid & utxo index
	utxoHash, err := chainhash.NewHashFromStr(params.collateralUTXOForMiner.txid)
	if err != nil {
		panic(err)
	}
	outPoint := wire.NewOutPoint(utxoHash, params.collateralUTXOForMiner.utxo)
	txIn := wire.NewTxIn(outPoint, nil, nil)

	// a new tx
	redeemTx := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
	redeemTx.AddTxIn(txIn)
	redeemTx.AddTxOut(redeemTxOutBurn)

	// signing the tx
	fmt.Println("preA: ", hex.EncodeToString(params.preA))
	fmt.Println("preB: ", hex.EncodeToString(params.preB))

	// activate OP_CSV
	// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
	// https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki

	siga, err := txscript.RawTxInSignature(redeemTx, 0, redeemScript, txscript.SigHashAll, params.AlicePrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	sigb, err := txscript.RawTxInSignature(redeemTx, 0, redeemScript, txscript.SigHashAll, params.BobPrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	//!!! everything below is NOT covered by signatures.
	// See https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

	signature := txscript.NewScriptBuilder()

	signature.AddData(params.preB)
	signature.AddData(params.preA)

	signature.AddOp(txscript.OP_0) // deal with the off-by-one error in CHECKMULTISIG https://learnmeabitcoin.com/technical/p2ms
	signature.AddData(siga)
	signature.AddData(sigb)
	signature.AddData(redeemScript)

	signatureScript, err := signature.Script()
	if err != nil {
		panic(err)
	}

	redeemTx.TxIn[0].SignatureScript = signatureScript

	var signedTx bytes.Buffer
	redeemTx.Serialize(&signedTx)

	hexSignedTx := hex.EncodeToString(signedTx.Bytes())

	return hexSignedTx
}
