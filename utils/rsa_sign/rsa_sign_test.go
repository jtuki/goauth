package rsa_sign

import (
	"testing"
	"github.com/jtuki/goauth/utils/rsa_auth"
	"crypto"
	"crypto/rand"
)

func TestSignVerify(t *testing.T) {
	priv, pub, err := rsa_auth.GenKey(512)
	if err != nil {
		t.Fatalf("gen key failed: err[%v]", err)
		return
	}
	
	raw := make([]byte, 10240)
	if _, err = rand.Read(raw); err != nil {
		t.Fatalf("rand read failed: err[%v]", err)
		return
	}
	
	// 签名/验证签名使用的盐长度
	saltLength := 30 // or 0,-1
	
	signature, err := GenSign(crypto.SHA256, priv, saltLength, raw)
	if err != nil {
		t.Fatalf("gen sign failed: err[%v]", err)
		return
	}
	
	if err = VerifySign(crypto.SHA256, pub, saltLength, raw, signature); err != nil {
		t.Fatalf("verify sign failed: err[%v]", err)
		return
	}
	
	// 盐的长度不能太长，否则会出错！（同上面使用的 RSA512 有关，修改成 RSA1024 则可以使用更长的盐字节序列）
	saltLength = 31
	signature, err = GenSign(crypto.SHA256, priv, saltLength, raw)
	if err == nil {
		t.Fatalf("gen sign failed: err[%v]", err)
		return
	}
}