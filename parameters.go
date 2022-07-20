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

	expectedTxDepAlice string
	expectedTxDepBob   string
	expectedTxColBob   string
	expectedTxColMiner string
}

type TestingUTXO struct {
	txid   string
	utxo   uint32
	amount int64
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
			txid:   "2717ebb6098623304b88e2b51f69e255229a8fc5e6cfd9dfa9e7f02f21721dd5",
			utxo:   1,
			amount: 200000,
		},

		depositUTXOForBob: TestingUTXO{
			txid:   "60f72390952124ba171bb464395fc5f82ebb5eb67767151955ec36c1085c3ac4",
			utxo:   1,
			amount: 200000,
		},

		collateralUTXOForBob: TestingUTXO{
			txid:   "e80fcfb0a1ce936fcb9b514f03d2d78d4c8f06a0657e3a9f54411dee636d1ce6",
			utxo:   0,
			amount: 100500,
		},
		collateralUTXOForMiner: TestingUTXO{
			txid:   "af3952ff7ba660ee035e876a56bdaf577cada78b938c83a874ff34460cad6320",
			utxo:   0,
			amount: 100500,
		},

		expectedTxDepAlice: "02000000000101d51d72212ff0e7a9dfd9cfe6c58f9a2255e2691fb5e2884b30238609b6eb17270100000000ffffffff02f824010000000000160014b7ec1691e6763acf02abb97d799a784b4ff3db86a8610000000000001600146b758673561ff5725c50513f784f9f507f28de31052031306131653439653263353632393565316632666432646365373832393464610048304502210090de6d391b3b242537752240bcc18377f553c44f3163b6dc7d586df0a8617fd502206d3843c88d29132d2121a181dbacfd0dca3cbf3a9a9ba877011ae0875b63772901483045022100a57bd089ff686c36dec8d0c2ec390d36abb2129f0bca7fcdc8f72c98fead7b9c02207de2e8a71f334020aba7da1ddde901bff4671d64c26e89079dda2fcfefd1fb91017c52210272fc1a56b46948a9071eafa0daef7e1c37a943e7db2b3de703e78e25d3edece72103f546edf7b434b50aa0115c1c82a0f9a96505d9eff55d2fe3b848c4b51c06b64352afa9141bf351d042f4dc4f2ca667d6523db196ba5e0a1b8763516752b275a914bfbf4dd90b482da06655a307947f325168eff185876800000000",
		expectedTxDepBob:   "02000000000101c43a5c08c136ec5519156777b65ebb2ef8c55f3964b41b17ba2421959023f7600100000000020000000194880100000000002200201033fb3f2960888023aa207050961a4b1c065634019976628b7dce37e4ff7acf0620306463376334373734306137343861626564313932303632663063616636333701000048304502210099a0b5ee636a3cd75fa865e98ab742d21a22e5d1a1b49b359f3e94c690a90ad5022025f161c12318d66920d56d7781a3b2de520bcbc2b7ca176aca3887833df00c8001473044022075829af05233ed77ec686f000809f2ecb1720c336e331e31ef7714e4a502cb1402201de952770169c272088f860c66f604855e31e05c6f06f6f1e335cc1b37820d9b017c52210272fc1a56b46948a9071eafa0daef7e1c37a943e7db2b3de703e78e25d3edece72103f546edf7b434b50aa0115c1c82a0f9a96505d9eff55d2fe3b848c4b51c06b64352afa9141bf351d042f4dc4f2ca667d6523db196ba5e0a1b8763516752b275a914bfbf4dd90b482da06655a307947f325168eff185876800000000",
		expectedTxColBob:   "02000000000101e61c6d63ee1d41549f3a7e65a0068f4c8dd7d2034f519bcb6f93cea1b0cf0fe800000000000200000001a0860100000000001600146b758673561ff5725c50513f784f9f507f28de3105010000483045022100adef6bde2f7e5ab247849d7a3d983e4d402b875ac1f6e522384e0b01c57129dc022077d87ff1e0d99024277fbc4fdac55a63679b8a579c0503f7bece051233db2c410148304502210097ebfc97a73426f55861e50334e2da9bc27d4acc4b874593ce181a4278670ffa022048836e29cec692ac151055302e8570970d5c166c8e56b9ce16e5885d45fa51cd017c52210272fc1a56b46948a9071eafa0daef7e1c37a943e7db2b3de703e78e25d3edece72103f546edf7b434b50aa0115c1c82a0f9a96505d9eff55d2fe3b848c4b51c06b64352afa9141bf351d042f4dc4f2ca667d6523db196ba5e0a1b8763a914bfbf4dd90b482da06655a307947f325168eff185876752b275516800000000",
		expectedTxColMiner: "020000000001012063ad0c4634ff74a8838c938ba7ad7c57afbd566a875e03ee60a67bff5239af0000000000ffffffff01f82401000000000017a91441c98a140039816273e50db317422c11c2bfcc88870620306463376334373734306137343861626564313932303632663063616636333720313061316534396532633536323935653166326664326463653738323934646100473044022027b083b2a6d527a864642112ed99d61745cc5ca3a7064333e9029c24d3a4da9002201198ea99c4c0ba82a7456f49f22b6f3e173ac13772471ad7a861229eabaa3a4b01483045022100e34cd74584db1a3adb8c921602dc4d1cd34239a2d24776e4edcfd705412698d0022049fe6f13644691b2cfc99b8c95f48ce62f256021487dc77d9d3aff18ccd45c30017c52210272fc1a56b46948a9071eafa0daef7e1c37a943e7db2b3de703e78e25d3edece72103f546edf7b434b50aa0115c1c82a0f9a96505d9eff55d2fe3b848c4b51c06b64352afa9141bf351d042f4dc4f2ca667d6523db196ba5e0a1b8763a914bfbf4dd90b482da06655a307947f325168eff185876752b275516800000000",
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

func (params *Parameters) GetCollateralUTXOForBob() *wire.OutPoint {
	utxoHash, err := chainhash.NewHashFromStr(params.collateralUTXOForBob.txid)
	if err != nil {
		panic(err)
	}
	return wire.NewOutPoint(utxoHash, params.collateralUTXOForBob.utxo)
}

func (params *Parameters) GetCollateralUTXOForMiner() *wire.OutPoint {
	utxoHash, err := chainhash.NewHashFromStr(params.collateralUTXOForMiner.txid)
	if err != nil {
		panic(err)
	}
	return wire.NewOutPoint(utxoHash, params.collateralUTXOForMiner.utxo)
}

func (params *Parameters) GetAliceBobPks() ([]byte, []byte) {
	return params.AlicePrivateKey.PrivKey.PubKey().SerializeCompressed(), params.BobPrivateKey.PrivKey.PubKey().SerializeCompressed()
}
