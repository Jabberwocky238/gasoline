package device

import (
	"bytes"
	"testing"
)

func TestKeypair(t *testing.T) {
	// 使用十六进制格式的密钥（不是Base64）
	publickeyhex := "14nWLDf+tZ6CXwC6WNEq/VWsbOoSr/yggbyRX17goEM="
	privatekeyhex := "sDy6PGozYyAzXlAZEyWyPtpibexfi08uvPg9pQBknn0="
	var publickey PublicKey
	var privatekey PrivateKey

	// 检查错误处理
	if err := publickey.FromBase64(publickeyhex); err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	if err := privatekey.FromBase64(privatekeyhex); err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// 从私钥生成公钥
	pubkeyfromprivate := privatekey.PublicKey()

	t.Logf("Public key: %x", publickey[:])
	t.Logf("Generated public key: %x", pubkeyfromprivate[:])

	// 验证公钥是否匹配
	if !bytes.Equal(publickey[:], pubkeyfromprivate[:]) {
		t.Fatal("publickey != privatekey.PublicKey()")
	}
}

func TestKeypairGeneration(t *testing.T) {
	// 测试密钥生成
	privatekey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// 从私钥生成公钥
	publickey := privatekey.PublicKey()

	// 验证公钥不为零
	var zero PublicKey
	if bytes.Equal(publickey[:], zero[:]) {
		t.Fatal("Generated public key is zero")
	}

	t.Logf("Generated private key: %x", privatekey[:])
	t.Logf("Generated public key: %x", publickey[:])
}
