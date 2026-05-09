package handshake

const (
	HandshakeVersion = 0x01
)

type HandshakeCode uint32

const (
	HandshakeOK          HandshakeCode = 0x00
	HandshakeUnknownFail HandshakeCode = 0x01
	HandshakeAuthFail    HandshakeCode = 0x02
	HandshakeQOS         HandshakeCode = 0x03
)

type HandshakeCryptoSuite uint16

var (
	CryptoSuite_NONE      HandshakeCryptoSuite = 0b00000000_00000001
	CryptoSuite_Wireguard HandshakeCryptoSuite = 0b00000000_00000010
)

type HandshakeState int

const (
	StateIdle HandshakeState = iota
	StateDone
	StateFailed
	// version, crypto suite, vni, [<count:Uint16>,[<offset:Uint16>,<key:Uint64>,<value>] pairs]
	StateClientHello
	// version, crypto suite, [<count:Uint16>,[<offset:Uint16>,<key:Uint64>,<value>] pairs] (maybe challenge)
	StateServerHello
	// (answer challenge)
	StateClientAnswer
	// (config)
	StateServerAssign
)
