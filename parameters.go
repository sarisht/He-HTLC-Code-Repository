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
		T:                   15, // set T and ell to be small values for testing purposes.
		ell:                 4,
		vcol:                25000,
		vdep:                75000,
		fee:                 500,

		depositUTXOForAlice: TestingUTXO{
			txid:         "7e684f73cf2d690987d855da1a8b46efe0d6663145386eac1edaed3433883133",
			utxo:         1,
			scriptPubKey: "0020c3989b9e192f01b8cf56ecefac706da1e27d07c65a4e8441dad5d778bedd4309",
			amount:       200000,
		},
		depositUTXOForBob: TestingUTXO{
			txid:         "7646f2aa75f267718e1ddf1162fe1fccb3dfe5c4dd12173633ba03585c224609",
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

		expectedAliceTx: "020000000001013331883334edda1eac6e38453166d6e0ef468b1ada55d88709692dcf734f687e0100000000ffffffff02f824010000000000160014b7ec1691e6763acf02abb97d799a784b4ff3db86a8610000000000001600146b758673561ff5725c50513f784f9f507f28de3105203130613165343965326335363239356531663266643264636537383239346461004830450221009c357a9540e43e57bc8978a5966f541db0e91849b86865e90ad0a455a61049840220203abeeda070cf20fa86add5784dbc412409a07955ed1f9820e32bc4148e9d96014730440220130feaf63fff6a575809293d0b0d486440a073c9ad931bf3b4562d6689d3e707022048724d845a008ce84f4a79ef1c28733369e2ec721b3e08f029f7781c851b027b017c52210272fc1a56b46948a9071eafa0daef7e1c37a943e7db2b3de703e78e25d3edece72103f546edf7b434b50aa0115c1c82a0f9a96505d9eff55d2fe3b848c4b51c06b64352afa9141bf351d042f4dc4f2ca667d6523db196ba5e0a1b876351675fb275a914bfbf4dd90b482da06655a307947f325168eff185876800000000",
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
