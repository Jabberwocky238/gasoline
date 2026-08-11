package noise

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Message sizes for the two Noise_IK messages.
const (
	// msg1 = e_pub(32) || AEAD(static_pub)(32+16) || AEAD(timestamp)(len+16)
	tagSize       = chacha20poly1305.Overhead // 16
	TimestampSize = 12                        // TAI64N

	InitiationSize = KeySize + (KeySize + tagSize) + (TimestampSize + tagSize) // 32+48+28 = 108
	ResponseSize   = KeySize + tagSize                                         // 32+16 = 48
)

var (
	// ErrDecrypt is returned when an AEAD open fails — an unauthenticated or
	// tampered handshake message. Callers treat it as "drop, do not reply".
	ErrDecrypt = errors.New("noise: decryption failed")
	// ErrShort is returned for a truncated handshake message.
	ErrShort = errors.New("noise: message too short")
)

// TransportKeys is the pair of directional keys the handshake yields.
// Send encrypts outbound frames; Recv decrypts inbound. The initiator's Send
// equals the responder's Recv and vice versa.
type TransportKeys struct {
	Send [hashSize]byte
	Recv [hashSize]byte
}

// Seal encrypts plaintext for sending under Send with the given counter.
// The caller owns counter uniqueness — a counter must never repeat under one
// key. Used by the control plane (post-handshake config frames) and, later,
// the data plane.
func (k TransportKeys) Seal(counter uint64, plaintext, aad []byte) ([]byte, error) {
	return seal(k.Send, counter, plaintext, aad)
}

// Open decrypts ciphertext received under Recv with the given counter.
func (k TransportKeys) Open(counter uint64, ciphertext, aad []byte) ([]byte, error) {
	return open(k.Recv, counter, ciphertext, aad)
}

// Initiator drives the client side of Noise_IK. Construct with NewInitiator,
// call WriteInitiation to produce msg1, then ReadResponse(msg2) to finish.
type Initiator struct {
	staticPriv PrivateKey
	staticPub  PublicKey
	remotePub  PublicKey // responder's static public key, known in advance (the "K" in IK)

	ephPriv PrivateKey
	ephPub  PublicKey

	chainKey [hashSize]byte
	hash     [hashSize]byte
	done     bool
}

// NewInitiator creates an initiator that will authenticate as staticPriv/Pub to
// a responder whose static public key is remotePub.
func NewInitiator(staticPriv PrivateKey, staticPub, remotePub PublicKey) *Initiator {
	i := &Initiator{staticPriv: staticPriv, staticPub: staticPub, remotePub: remotePub}
	i.chainKey, i.hash = initState(remotePub)
	return i
}

// WriteInitiation produces msg1 and mixes in the encrypted static key and
// timestamp. timestamp must be 12 bytes (TAI64N); the responder uses it to
// reject replays.
func (i *Initiator) WriteInitiation(timestamp []byte) ([]byte, error) {
	if len(timestamp) != TimestampSize {
		return nil, fmt.Errorf("noise: timestamp must be %d bytes", TimestampSize)
	}
	var err error
	i.ephPriv, i.ephPub, err = GenerateKey()
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, InitiationSize)

	// e
	i.hash = mixHash(i.hash, i.ephPub[:])
	out = append(out, i.ephPub[:]...)

	// es = DH(e, rs); ck, k = KDF2
	es, err := dh(i.ephPriv, i.remotePub)
	if err != nil {
		return nil, err
	}
	var k [hashSize]byte
	i.chainKey, k = kdf2(i.chainKey, es)

	// s: AEAD-encrypt our static public key under k with AAD = hash
	encStatic, err := seal(k, 0, i.staticPub[:], i.hash[:])
	if err != nil {
		return nil, err
	}
	i.hash = mixHash(i.hash, encStatic)
	out = append(out, encStatic...)

	// ss = DH(s, rs); ck, k = KDF2
	ss, err := dh(i.staticPriv, i.remotePub)
	if err != nil {
		return nil, err
	}
	i.chainKey, k = kdf2(i.chainKey, ss)

	// timestamp payload, AEAD under new k
	encTS, err := seal(k, 0, timestamp, i.hash[:])
	if err != nil {
		return nil, err
	}
	i.hash = mixHash(i.hash, encTS)
	out = append(out, encTS...)

	return out, nil
}

// ReadResponse consumes msg2 and derives the transport keys.
func (i *Initiator) ReadResponse(msg2 []byte) (TransportKeys, error) {
	if i.done {
		return TransportKeys{}, errors.New("noise: initiator already finished")
	}
	if len(msg2) != ResponseSize {
		return TransportKeys{}, ErrShort
	}
	var re PublicKey
	copy(re[:], msg2[:KeySize])
	empty := msg2[KeySize:]

	// e
	i.hash = mixHash(i.hash, re[:])

	// ee = DH(e, re)
	ee, err := dh(i.ephPriv, re)
	if err != nil {
		return TransportKeys{}, err
	}
	i.chainKey = kdf1(i.chainKey, ee)

	// se = DH(s, re)
	se, err := dh(i.staticPriv, re)
	if err != nil {
		return TransportKeys{}, err
	}
	i.chainKey = kdf1(i.chainKey, se)

	// decrypt the empty payload to authenticate the transcript
	var k [hashSize]byte
	i.chainKey, k = kdf2(i.chainKey, nil)
	if _, err := open(k, 0, empty, i.hash[:]); err != nil {
		return TransportKeys{}, ErrDecrypt
	}
	i.hash = mixHash(i.hash, empty)

	// split into transport keys; initiator: send=t1, recv=t2
	t1, t2 := kdf2(i.chainKey, nil)
	i.done = true
	return TransportKeys{Send: t1, Recv: t2}, nil
}

// Responder drives the server side. Construct with NewResponder, call
// ReadInitiation(msg1) to authenticate the client and recover its static
// public key + timestamp, then WriteResponse to produce msg2.
type Responder struct {
	staticPriv PrivateKey
	staticPub  PublicKey

	remoteStatic PublicKey // recovered from msg1
	remoteEph    PublicKey

	ephPriv PrivateKey
	ephPub  PublicKey

	chainKey [hashSize]byte
	hash     [hashSize]byte
	stage    int // 0=fresh, 1=read-initiation done
}

// NewResponder creates a responder identified by staticPriv/Pub.
func NewResponder(staticPriv PrivateKey, staticPub PublicKey) *Responder {
	r := &Responder{staticPriv: staticPriv, staticPub: staticPub}
	r.chainKey, r.hash = initState(staticPub)
	return r
}

// ReadInitiation authenticates msg1. On success it returns the client's static
// public key (its identity) and the 12-byte timestamp for replay checking. On
// AEAD failure it returns ErrDecrypt and the caller must drop silently.
func (r *Responder) ReadInitiation(msg1 []byte) (clientStatic PublicKey, timestamp []byte, err error) {
	if len(msg1) != InitiationSize {
		return PublicKey{}, nil, ErrShort
	}
	off := 0
	copy(r.remoteEph[:], msg1[off:off+KeySize])
	off += KeySize
	encStatic := msg1[off : off+KeySize+tagSize]
	off += KeySize + tagSize
	encTS := msg1[off:]

	// e
	r.hash = mixHash(r.hash, r.remoteEph[:])

	// es = DH(s, re)
	es, err := dh(r.staticPriv, r.remoteEph)
	if err != nil {
		return PublicKey{}, nil, err
	}
	var k [hashSize]byte
	r.chainKey, k = kdf2(r.chainKey, es)

	// decrypt client's static key
	staticPlain, err := open(k, 0, encStatic, r.hash[:])
	if err != nil {
		return PublicKey{}, nil, ErrDecrypt
	}
	copy(r.remoteStatic[:], staticPlain)
	r.hash = mixHash(r.hash, encStatic)

	// ss = DH(s, rs)
	ss, err := dh(r.staticPriv, r.remoteStatic)
	if err != nil {
		return PublicKey{}, nil, err
	}
	r.chainKey, k = kdf2(r.chainKey, ss)

	// decrypt timestamp
	tsPlain, err := open(k, 0, encTS, r.hash[:])
	if err != nil {
		return PublicKey{}, nil, ErrDecrypt
	}
	r.hash = mixHash(r.hash, encTS)

	r.stage = 1
	ts := make([]byte, len(tsPlain))
	copy(ts, tsPlain)
	return r.remoteStatic, ts, nil
}

// WriteResponse produces msg2 and derives the transport keys. Must be called
// after a successful ReadInitiation.
func (r *Responder) WriteResponse() ([]byte, TransportKeys, error) {
	if r.stage != 1 {
		return nil, TransportKeys{}, errors.New("noise: WriteResponse before ReadInitiation")
	}
	var err error
	r.ephPriv, r.ephPub, err = GenerateKey()
	if err != nil {
		return nil, TransportKeys{}, err
	}

	out := make([]byte, 0, ResponseSize)

	// e
	r.hash = mixHash(r.hash, r.ephPub[:])
	out = append(out, r.ephPub[:]...)

	// ee = DH(e, re)
	ee, err := dh(r.ephPriv, r.remoteEph)
	if err != nil {
		return nil, TransportKeys{}, err
	}
	r.chainKey = kdf1(r.chainKey, ee)

	// se = DH(e, rs)
	se, err := dh(r.ephPriv, r.remoteStatic)
	if err != nil {
		return nil, TransportKeys{}, err
	}
	r.chainKey = kdf1(r.chainKey, se)

	// encrypt empty payload
	var k [hashSize]byte
	r.chainKey, k = kdf2(r.chainKey, nil)
	encEmpty, err := seal(k, 0, nil, r.hash[:])
	if err != nil {
		return nil, TransportKeys{}, err
	}
	r.hash = mixHash(r.hash, encEmpty)
	out = append(out, encEmpty...)

	// split; responder: send=t2, recv=t1 (mirror of initiator)
	t1, t2 := kdf2(r.chainKey, nil)
	return out, TransportKeys{Send: t2, Recv: t1}, nil
}

// RemoteStatic returns the client static key recovered by ReadInitiation.
func (r *Responder) RemoteStatic() PublicKey { return r.remoteStatic }

// --------------- helpers ---------------

// initState seeds the chaining key and hash with the construction string and
// the responder's static public key (the IK precondition).
func initState(responderStatic PublicKey) (chainKey, hash [hashSize]byte) {
	// WireGuard: ck = HASH(construction); h = HASH(ck || identifier); then mix rs.
	chainKey = blake2sSum([]byte(noiseConstruction))
	hash = mixHash(chainKey, []byte(gasolineIdentifier))
	hash = mixHash(hash, responderStatic[:])
	return chainKey, hash
}

func blake2sSum(b []byte) [hashSize]byte {
	h, _ := newBlake2s()
	h.Write(b)
	var out [hashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

func seal(key [hashSize]byte, counter uint64, plaintext, aad []byte) ([]byte, error) {
	a, err := aeadKey(key)
	if err != nil {
		return nil, err
	}
	n := nonce(counter)
	return a.Seal(nil, n[:], plaintext, aad), nil
}

func open(key [hashSize]byte, counter uint64, ciphertext, aad []byte) ([]byte, error) {
	a, err := aeadKey(key)
	if err != nil {
		return nil, err
	}
	n := nonce(counter)
	return a.Open(nil, n[:], ciphertext, aad)
}
