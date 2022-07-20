package hehtlc

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type Parameters struct {
	preA []byte
	preB []byte

	AlicePrivateKey *btcutil.WIF
	BobPrivateKey   *btcutil.WIF

	Alice2Bech32Address string
	Bob2Bech32Address   string

	ell int64
	T   int64

	vdep int64
	vcol int64
	fee  int64

	depositUTXOForAlice    TestingUTXO
	depositUTXOForBob      TestingUTXO
	collateralUTXOForBob   TestingUTXO
	collateralUTXOForMiner TestingUTXO

	expectedAliceTx string
}

type TestingUTXO struct {
	txid         string
	utxo         uint32
	scriptPubKey string /// needed by the new signing algorithm in BIP-143
	amount       int64
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
		// Bech32 testnet pubkey hash or script hash https://en.bitcoin.it/wiki/List_of_address_prefixes
		Alice2Bech32Address: "tb1qklkpdy0xwcav7q4th97hnxncfd8l8kux4u7pwn",
		Bob2Bech32Address:   "tb1qdd6cvu6krl6hyhzs2ylhsnul2plj3h330kgfz6",
		T:                   2, // set T and ell to be small values for testing purposes.
		ell:                 2,
		vcol:                25000,
		vdep:                75000,
		fee:                 500,

		depositUTXOForAlice: TestingUTXO{
			txid:         "2717ebb6098623304b88e2b51f69e255229a8fc5e6cfd9dfa9e7f02f21721dd5",
			utxo:         1,
			scriptPubKey: "0020c3989b9e192f01b8cf56ecefac706da1e27d07c65a4e8441dad5d778bedd4309",
			amount:       200000,
		},
		depositUTXOForBob: TestingUTXO{
			txid:         "6b9fb0ae80cae40deb641322f2f2104712f3bed1b1d2b2b6c6e4c37f1af0f58f",
			utxo:         0,
			scriptPubKey: "0020c3989b9e192f01b8cf56ecefac706da1e27d07c65a4e8441dad5d778bedd4309",
			amount:       200000,
		},
		collateralUTXOForBob: TestingUTXO{
			txid: "",
			utxo: 0,
		},
		collateralUTXOForMiner: TestingUTXO{
			txid: "",
			utxo: 0,
		},

		expectedAliceTx: "02000000000101d51d72212ff0e7a9dfd9cfe6c58f9a2255e2691fb5e2884b30238609b6eb17270100000000ffffffff02f824010000000000160014b7ec1691e6763acf02abb97d799a784b4ff3db86a8610000000000001600146b758673561ff5725c50513f784f9f507f28de31052031306131653439653263353632393565316632666432646365373832393464610048304502210090de6d391b3b242537752240bcc18377f553c44f3163b6dc7d586df0a8617fd502206d3843c88d29132d2121a181dbacfd0dca3cbf3a9a9ba877011ae0875b63772901483045022100a57bd089ff686c36dec8d0c2ec390d36abb2129f0bca7fcdc8f72c98fead7b9c02207de2e8a71f334020aba7da1ddde901bff4671d64c26e89079dda2fcfefd1fb91017c52210272fc1a56b46948a9071eafa0daef7e1c37a943e7db2b3de703e78e25d3edece72103f546edf7b434b50aa0115c1c82a0f9a96505d9eff55d2fe3b848c4b51c06b64352afa9141bf351d042f4dc4f2ca667d6523db196ba5e0a1b8763516752b275a914bfbf4dd90b482da06655a307947f325168eff185876800000000",
	}

	return params
}

func (params *Parameters) GetAliceAddressOrPanic() btcutil.Address {
	a, err := btcutil.DecodeAddress(params.Alice2Bech32Address, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}
	return a
}

func (params *Parameters) GetBobAddressOrPanic() btcutil.Address {
	a, err := btcutil.DecodeAddress(params.Bob2Bech32Address, &chaincfg.TestNet3Params)
	if err != nil {
		panic(err)
	}
	return a
}

func (params *Parameters) GetDepositUTXO4Alice() *wire.OutPoint {
	utxoHash, err := chainhash.NewHashFromStr(params.depositUTXOForAlice.txid)
	if err != nil {
		panic(err)
	}
	return wire.NewOutPoint(utxoHash, params.depositUTXOForAlice.utxo)
}

func (params *Parameters) GetDepositUTXOForBob() *wire.OutPoint {
	utxoHash, err := chainhash.NewHashFromStr(params.depositUTXOForBob.txid)
	if err != nil {
		panic(err)
	}
	return wire.NewOutPoint(utxoHash, params.depositUTXOForBob.utxo)
}

func (params *Parameters) GetAliceBobPks() ([]byte, []byte) {
	return params.AlicePrivateKey.PrivKey.PubKey().SerializeCompressed(), params.BobPrivateKey.PrivKey.PubKey().SerializeCompressed()
}
