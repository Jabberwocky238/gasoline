/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/curve25519"
)

const KeyLength = 32

type (
	Key        [KeyLength]byte
	PublicKey  [KeyLength]byte
	PrivateKey [KeyLength]byte
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func parseKeyBase64(s string) (*Key, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("Invalid key: " + err.Error())
	}
	if len(k) != KeyLength {
		return nil, errors.New("Keys must decode to exactly 32 bytes")
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func (sk *PrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

func (sk *PrivateKey) FromHex(src string) (err error) {
	err = loadExactHex(sk[:], src)
	sk.clamp()
	return
}

func (sk *PrivateKey) FromBase64(src string) (err error) {
	key, err := parseKeyBase64(src)
	if err != nil {
		return err
	}
	copy(sk[:], key[:])
	return nil
}

func (sk *PrivateKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(sk[:])
}

func (pk *PublicKey) FromBase64(src string) (err error) {
	key, err := parseKeyBase64(src)
	if err != nil {
		return err
	}
	copy(pk[:], key[:])
	return nil
}

func (pk *PublicKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(pk[:])
}

func (pk *PublicKey) FromHex(src string) (err error) {
	err = loadExactHex(pk[:], src)
	return err
}

func (sk *PrivateKey) PublicKey() (pk PublicKey) {
	apk := (*[KeyLength]byte)(&pk)
	ask := (*[KeyLength]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func NewPrivateKey() (sk PrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

func Encrypt(plaintext []byte, publicKey PublicKey) []byte {
	// 简单的凯撒编码，位移量为3
	shift := 3
	ciphertext := make([]byte, len(plaintext))

	for i, b := range plaintext {
		ciphertext[i] = byte((int(b) + shift) % 256)
	}

	return ciphertext
}

func Decrypt(ciphertext []byte, privateKey PrivateKey) []byte {
	// 简单的凯撒解码，位移量为3
	shift := 3
	plaintext := make([]byte, len(ciphertext))

	for i, b := range ciphertext {
		plaintext[i] = byte((int(b) - shift + 256) % 256)
	}

	return plaintext
}
