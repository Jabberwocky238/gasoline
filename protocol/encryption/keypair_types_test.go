package encryption

import (
	"bytes"
	"testing"
)

func TestKeypair(t *testing.T) {
	publickeyhex := "14nWLDf+tZ6CXwC6WNEq/VWsbOoSr/yggbyRX17goEM="
	privatekeyhex := "sDy6PGozYyAzXlAZEyWyPtpibexfi08uvPg9pQBknn0="
	var publickey PublicKey
	var privatekey PrivateKey

	if err := publickey.FromBase64(publickeyhex); err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}
	if err := privatekey.FromBase64(privatekeyhex); err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	pubkeyfromprivate := privatekey.PublicKey()

	if !bytes.Equal(publickey[:], pubkeyfromprivate[:]) {
		t.Fatal("publickey != privatekey.PublicKey()")
	}
}

func TestKeypairGeneration(t *testing.T) {
	privatekey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	publickey := privatekey.PublicKey()

	var zero PublicKey
	if bytes.Equal(publickey[:], zero[:]) {
		t.Fatal("Generated public key is zero")
	}
}
