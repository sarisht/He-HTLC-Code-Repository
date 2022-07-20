package main

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

type Parameters struct {
	preA []byte
	preB []byte

	AlicePrivateKey *btcutil.WIF
	BobPrivateKey   *btcutil.WIF

	Alice2PubKey string
	Bob2PubKey   string

	ell int64
	T   int64

	vdep uint32
	vcol uint32
	fee  uint32

	depositUTXO4Alice    TestingUTXO
	depositUTXO4Bob      TestingUTXO
	collateralUTO4Bob    TestingUTXO
	collateralUTXO4Miner TestingUTXO
}

type TestingUTXO struct {
	txid string
	utxo uint32
}

func GenTestParams() Parameters {
	AlicePrivateKey, err := btcutil.DecodeWIF("cNnZ1uE6Eb3o2Ziuo2GBTNZxmjJqi3aoj4CHLkfm7as8Z9ruuRcE")
	if err != nil {
		panic(err)
	}

	BobPrivateKey, err := btcutil.DecodeWIF("cVgxEkRBtnfvd41ssd4PCsiemahAHidFrLWYoDBMNojUeME8dojZ")
	if err != nil {
		panic(err)
	}

	params := Parameters{
		preA:            []byte("10a1e49e2c56295e1f2fd2dce78294da"),
		preB:            []byte("0dc7c47740a748abed192062f0caf637"),
		AlicePrivateKey: AlicePrivateKey,
		BobPrivateKey:   BobPrivateKey,
		Alice2PubKey:    "tb1qklkpdy0xwcav7q4th97hnxncfd8l8kux4u7pwn",
		Bob2PubKey:      "tb1qdd6cvu6krl6hyhzs2ylhsnul2plj3h330kgfz6",
		T:               15,
		ell:             4,
		depositUTXO4Alice: TestingUTXO{
			txid: "7e684f73cf2d690987d855da1a8b46efe0d6663145386eac1edaed3433883133",
			utxo: 1,
		},
		depositUTXO4Bob: TestingUTXO{
			txid: "",
			utxo: 0,
		},
		collateralUTO4Bob: TestingUTXO{
			txid: "",
			utxo: 0,
		},
		collateralUTXO4Miner: TestingUTXO{
			txid: "",
			utxo: 0,
		},
		vcol: 25000,
		vdep: 75000,
		fee:  500,
	}

	return params
}

const (
	Alice = iota
	Bob
)

func main() {
	depositScript, depositAddr := BuildDepositContract()
	fmt.Println("witness script (asm):", func() string {
		s, _ := txscript.DisasmString(depositScript)
		return s
	}())
	fmt.Println("witness script (hex):", hex.EncodeToString(depositScript))
	fmt.Println("P2WSH Deposit address:", depositAddr)
	// fmt.Println("P2SH Collateral address:", BuildHeHTLCCollateralP2SHAddr())

	// /*
	// 	TEST 1: DEPOSIT SPENT by ALICE (to Alice and Bob) (Dep-A)
	// 	Success.
	// 	Testnet tx: https://www.blockchain.com/btc-testnet/tx/6dc135484d4327ae4208043db961f25231c457d02723b94dd44d64a9368e7365
	// */
	fmt.Println("spend by Alice:", SpendHeHTLCDepositAlice())

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

func BuildDepositContract() ([]byte, string) {
	params := GenTestParams()

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
	builder.AddInt64(params.T)
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP) // drop T from stack

	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(hash_preb)
	builder.AddOp(txscript.OP_EQUAL)

	builder.AddOp(txscript.OP_ENDIF)

	redeemScript, err := builder.Script()
	if err != nil {
		panic(err)
	}

	// witness program is 0 || SHA256 hash of witness script
	witnessProgram := sha256.Sum256(redeemScript)

	fmt.Println("witness program", hex.EncodeToString(witnessProgram[:]))

	// if using Bitcoin main net then pass &chaincfg.MainNetParams as second argument
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}

	return redeemScript, addr.EncodeAddress()
}

func BuildCollateralContract() []byte {
	params := GenTestParams()

	// public keys extracted from wif.PrivKey
	pk1 := params.AlicePrivateKey.PrivKey.PubKey().SerializeCompressed()
	pk2 := params.BobPrivateKey.PrivKey.PubKey().SerializeCompressed()

	hash_prea := btcutil.Hash160(params.preA)
	hash_preb := btcutil.Hash160(params.preB)

	builder := txscript.NewScriptBuilder()

	// corresponding sigscript
	// t >= l || sigA || sigB, or
	// preB || preA || sigA || sigB
	builder.AddOp(txscript.OP_2)
	builder.AddData(pk1).AddData(pk2)
	builder.AddOp(txscript.OP_2)
	builder.AddOp(txscript.OP_CHECKMULTISIGVERIFY)

	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(hash_prea)
	builder.AddOp(txscript.OP_EQUAL)

	builder.AddOp(txscript.OP_IF) // if Alice provides pre_a, the script ends here
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(hash_preb)
	builder.AddOp(txscript.OP_EQUAL)

	builder.AddOp(txscript.OP_ELSE) // else, check Bob's input
	builder.AddInt64(params.ell)
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP) // drop ell from stack
	builder.AddOp(txscript.OP_TRUE)
	builder.AddOp(txscript.OP_ENDIF)

	redeemScript, err := builder.Script()
	if err != nil {
		panic(err)
	}
	return redeemScript
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

func BuildHeHTLCCollateralP2SHAddr() string {
	redeemScript := BuildCollateralContract()

	// calculate the hash160 of the redeem script
	redeemHash := btcutil.Hash160(redeemScript)

	// if using Bitcoin main net then pass &chaincfg.MainNetParams as second argument
	addr, err := btcutil.NewAddressScriptHashFromHash(redeemHash, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}

	return addr.EncodeAddress()
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

func SpendHeHTLCDepositAlice() string {
	params := GenTestParams()
	// output address
	decodedAddrAlice, err := btcutil.DecodeAddress(params.Alice2PubKey, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}
	destinationAddrByteAlice, err := txscript.PayToAddrScript(decodedAddrAlice)
	if err != nil {
		panic(err)
	}
	decodedAddrBob, err := btcutil.DecodeAddress(params.Bob2PubKey, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}
	destinationAddrByteBob, err := txscript.PayToAddrScript(decodedAddrBob)
	if err != nil {
		panic(err)
	}
	redeemTxOutAlice := wire.NewTxOut(int64(params.vdep), destinationAddrByteAlice)
	redeemTxOutBob := wire.NewTxOut(int64(params.vcol), destinationAddrByteBob)

	witnessScript, _ := BuildDepositContract()

	// txid & utxo index
	utxoHash, err := chainhash.NewHashFromStr(params.depositUTXO4Alice.txid)
	if err != nil {
		panic(err)
	}
	outPoint := wire.NewOutPoint(utxoHash, params.depositUTXO4Alice.utxo)
	txIn := wire.NewTxIn(outPoint, nil, nil)

	// a new tx
	redeemTx := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
	redeemTx.AddTxIn(txIn)
	redeemTx.AddTxOut(redeemTxOutAlice)
	redeemTx.AddTxOut(redeemTxOutBob)

	// sign with BIP-143
	// sigPubKey of the input
	pkscript, err := hex.DecodeString("0014ae593174c032aa62935500e323cd6e125aff92e6")
	if err != nil {
		panic(err)
	}
	amount := int64(20_0000)
	prevOutput := txscript.NewCannedPrevOutputFetcher(pkscript, amount)

	sigHash := txscript.NewTxSigHashes(redeemTx, prevOutput)

	siga, err := txscript.RawTxInWitnessSignature(redeemTx, sigHash, 0, amount, witnessScript, txscript.SigHashAll, params.AlicePrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	sigb, err := txscript.RawTxInWitnessSignature(redeemTx, sigHash, 0, amount, witnessScript, txscript.SigHashAll, params.BobPrivateKey.PrivKey)
	if err != nil {
		panic(err)
	}

	//!!! everything below is NOT covered by signatures.
	// See https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

	// witness stack
	//signature := txscript.NewScriptBuilder()
	//
	//signature.AddData(params.preA)
	//signature.AddOp(txscript.OP_0) // deal with the off-by-one error in CHECKMULTISIG https://learnmeabitcoin.com/technical/p2ms
	//signature.AddData(siga)
	//signature.AddData(sigb)
	//signature.AddData(witnessScript)
	//
	//signatureScript, err := signature.Script()
	//if err != nil {
	//	panic(err)
	//}

	redeemTx.TxIn[0].Witness = wire.TxWitness{
		params.preA,
		[]byte{}, // dummy value for MULTISIG must be empty per https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
		siga,
		sigb,
		witnessScript,
	}

	var signedTx bytes.Buffer
	redeemTx.Serialize(&signedTx)

	hexSignedTx := hex.EncodeToString(signedTx.Bytes())

	return hexSignedTx
}

func SpendHeHTLCDepositBob() string {

	params := GenTestParams()

	redeemScript, _ := BuildDepositContract()

	collateralAddr := BuildHeHTLCCollateralP2SHAddr()

	// txid & utxo index
	utxoHash, err := chainhash.NewHashFromStr(params.depositUTXO4Bob.txid)
	if err != nil {
		panic(err)
	}
	outPoint := wire.NewOutPoint(utxoHash, params.depositUTXO4Bob.utxo)
	txIn := wire.NewTxIn(outPoint, nil, nil)

	// a new tx
	redeemTx := wire.NewMsgTx(2) // need version 2 to use OP_CSV (https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
	redeemTx.AddTxIn(txIn)

	decodedAddrCol, err := btcutil.DecodeAddress(collateralAddr, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}
	destinationAddrByteCol, err := txscript.PayToAddrScript(decodedAddrCol)
	if err != nil {
		panic(err)
	}

	redeemTxOutCol := wire.NewTxOut(int64(params.vdep)+int64(params.vcol)+int64(params.fee), destinationAddrByteCol)

	redeemTx.AddTxOut(redeemTxOutCol)

	// signing the tx
	fmt.Println("preA: ", hex.EncodeToString(params.preA))
	fmt.Println("preB: ", hex.EncodeToString(params.preB))

	// activate OP_CSV
	// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
	// https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
	redeemTx.TxIn[0].Sequence = uint32(params.T)

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
	signature.AddOp(txscript.OP_0) // add dummy value to be consumed by first OP_HASH160

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

func SpendHeHTLCCollateralBob() string {

	params := GenTestParams()

	redeemScript := BuildCollateralContract()

	decodedAddrBob, err := btcutil.DecodeAddress(params.Bob2PubKey, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}
	destinationAddrByteBob, err := txscript.PayToAddrScript(decodedAddrBob)
	if err != nil {
		panic(err)
	}
	redeemTxOutBob := wire.NewTxOut(int64(params.vcol)+int64(params.vdep), destinationAddrByteBob)

	// txid & utxo index
	utxoHash, err := chainhash.NewHashFromStr(params.collateralUTO4Bob.txid)
	if err != nil {
		panic(err)
	}
	outPoint := wire.NewOutPoint(utxoHash, params.collateralUTO4Bob.utxo)
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

	redeemScript := BuildCollateralContract()

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
	utxoHash, err := chainhash.NewHashFromStr(params.collateralUTXO4Miner.txid)
	if err != nil {
		panic(err)
	}
	outPoint := wire.NewOutPoint(utxoHash, params.collateralUTXO4Miner.utxo)
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
