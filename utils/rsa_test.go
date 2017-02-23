package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRsaPrivateKeyGeneration(t *testing.T) {
	var priv *rsa.PrivateKey
	var pub *rsa.PublicKey
	var err error

	priv, pub, err = RsaPrivateKeyGeneration(256)
	if err != nil {
		t.Fatalf("key generate failed")
	}
	fmt.Println(*priv)
	fmt.Println(*pub)

	priv, pub, err = RsaPrivateKeyGeneration(1024)
	if err != nil {
		t.Fatalf("key generate failed")
	}
	fmt.Println(*priv)
	fmt.Println(*pub)

	priv, pub, err = RsaPrivateKeyGeneration(2048)
	if err != nil {
		t.Fatalf("key generate failed")
	}
	fmt.Println(*priv)
	fmt.Println(*pub)
}

func TestRsaPrivateKeyEncodeToPEM(t *testing.T) {
	f_test := func(bits int, pwd string) {
		var priv *rsa.PrivateKey
		var err error

		fmt.Printf("* bits[%d], pwd[%s]\n", bits, pwd)

		priv, _, err = RsaPrivateKeyGeneration(bits)
		if err != nil {
			t.Fatalf("key generate failed")
		}

		pemBytes, err := RsaPrivateKeyEncodeToPEM(priv, pwd)
		if err != nil {
			t.Fatalf("generate pem failed")
		}

		fmt.Printf("%s\n", pemBytes)
	}

	f_test(256, "simple_password")
	f_test(256, "")
	f_test(1024, "simple_password")
	f_test(1024, "")
}

func TestRsaPrivateKeyEqual(t *testing.T) {
	// 两个随机生成的 privateKey 对象，不应该相同
	privGen1, _, _ := RsaPrivateKeyGeneration(512)
	privGen2, _, _ := RsaPrivateKeyGeneration(512)
	if RsaPrivateKeyEqual(privGen1, privGen2) {
		t.Fatalf("should not be equal")
	}

	const (
		pemBlock1Password = ""
		pemBlock1         = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC4GZ3kbKQNp6ztnL2JV6wu2BhO0g55lXPuyMMd5kDn1WkK7YV6
gDCMR1Bg2n4mqdROn8nLqJpbKasaTCf9GmzTQWr6LtWc5WY8MH5Vc0CwhV20qW3Q
XF1Fs7lDkrDEyeFi/BfQ+u0MnGJqJGIBix315B5wlfNKbc7kgiePoDu3uwIDAQAB
AoGAO728WgrTNccqu7S4YOA9dLoVMUbDAbt48ozdnE9C0riTLMOlI/qDRpJByBw/
AabsyVLa9ibRaDHeX1tFQsIXe+zxvTpKzf15hHC7fkvS7hD4elXdm9K6L4o+1Qtv
p8SbdLSDnbprj6ubveRjxZsa5lkz2uG3bWqIU+mELhr3cEECQQDGiPcVyuwyHZEj
FesKAprrIdWIgIbEli/yoTy3fUdhDzv10HXabkbjdh55nqK+6IsO1N0l0iU7Wi/z
Bogu/MDhAkEA7WMNH+cXl8jFgfR+sLrm3MIY53X8/qMsknHAEqxX3I7fGeuB6T1r
iTCNxme3pb40h/TeFlaslSE4a0GhiB9gGwJBAI9PUORHPWYTl6+245mvNbqjCqtk
82M2clf28YgWA49ZWtPe7SOGVN9eZTMvQpUB8Vb8asIhRkTonhIUVfts8aECQHwW
tPuiPzD2oFfoSHl1mcx4IbCMeq1Y+qmqkG6ybFM8096mvwf/NUFHgjTebp9TJ/6R
v64JrLlf3jAi5J9VV1UCQAyfU4EojfFB98uH6DtMf25tw//GcxgX8f5en2/vhM5G
HGCjMym57eiZInyouxKYIOpGBDkkbigMj/AnQN8xmsY=
-----END RSA PRIVATE KEY-----
		`

		pemBlock2Password = "simple_password"
		pemBlock2         = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,fa0952819bea6766f925345205091f66

fAknzcduzwgQL5lVMxNREoGqin+NmDhpTfRyBreU4nuEnzIMUHJS98RdrxJ4MX/5
aREyTIAUHt/7BMTayNroJ8O/MPWJmgZfKr3hGsNgeuvlf+JVUuMscxDLLYgl0nIZ
u+69lKeidAJhcu2bVCMMEpMbZ/oESAdu3+TvHpt7VNOmxwdewPhr7uCpe3VRlg3Z
KwIoD4FXDRlYyOnAXmllFv9ZqHCEUDAxta9Ct1+zxHPosi6dRe59Y4ko9OeGMUbY
nVlRZ07dIlVnSeHO7Ik/Bx06e2NuUiiVWnAyupiPnmERmUtzQ62fiq8TK+mK/Imz
zHqIaLIWP+xPsSMvV7GdaXBmSV+pvpX3ucNjCRAtRwgo+Tpzyf8YXqSUGlTT9CB3
mUk4YrBb8IBpw19XYkA0DxiFpT+ow3u+5feha/xIrtN3qPJRc/CJ8+vMxHuklrb2
XrSc4IswJ7ld4s+7Jt7TtPQ2TXdRexpwQPIoj/pWHZe41oiwtlNBsq93jKvRTx14
hCZBFl5VbUhZrkSP9nKil7+YXdhZ/tC/fTH3RH7D/FKmdtfTZVuyZ/HmyfswkbpQ
4lhp4Dp0IpWr64F686RJUR2rFK9wxip3Gei366XtV08hqNlQ6HQVBcOgS0WJvkAa
KUw9TI4kcjKfib1Zsdt0FxU/yDe+uXbLTp67eEFq8gk5A+Avavw9aEuGfLDF+VWI
IIUfv2svE4v9MiCUIu/7MdpkMMReN+D1eJfqCqJueDu6SYP/2RJkKfdaYgNqCiCS
B45YrXa1TEROBapQgwFej25VZGGDjpG7y6w1DPP72+8=
-----END RSA PRIVATE KEY-----
		`
	)

	var err1, err2 error

	privGen1, _, err1 = RsaPrivateKeyDecodeFromPEM([]byte(pemBlock1), pemBlock1Password)
	privGen2, _, err2 = RsaPrivateKeyDecodeFromPEM([]byte(pemBlock1), pemBlock1Password)
	if err1 != nil || err2 != nil || !RsaPrivateKeyEqual(privGen1, privGen2) {
		t.Fatalf("should be equal; err1[%v], err2[%v]", err1, err2)
	}

	privGen1, _, _ = RsaPrivateKeyDecodeFromPEM([]byte(pemBlock2), pemBlock2Password)
	privGen2, _, _ = RsaPrivateKeyDecodeFromPEM([]byte(pemBlock2), pemBlock2Password)
	if err1 != nil || err2 != nil || !RsaPrivateKeyEqual(privGen1, privGen2) {
		t.Fatalf("should be equal; err1[%v], err2[%v]", err1, err2)
	}
}

func TestRsaPrivateKeyDecodeFromPEM(t *testing.T) {
	f_test := func(bits int, pwd string) {
		privGen, _, err := RsaPrivateKeyGeneration(bits)
		if err != nil {
			t.Fatalf("key generate failed")
		}

		pemBytes1, err := RsaPrivateKeyEncodeToPEM(privGen, pwd)
		if err != nil {
			t.Fatalf("encode to PEM failed")
		}

		privDecoded, _, err := RsaPrivateKeyDecodeFromPEM(pemBytes1, pwd)
		if err != nil {
			t.Fatalf("decode from PEM failed")
		}

		if !RsaPrivateKeyEqual(privGen, privDecoded) {
			t.Fatalf("pem not equal")
		}
	}

	f_test(256, "simple_password")
	f_test(256, "")
	f_test(1024, "simple_password")
	f_test(1024, "")
}

func TestRsaPrivateKeyBitSize(t *testing.T) {
	f_test := func(bits int) {
		priv, _, _ := RsaPrivateKeyGeneration(bits)
		if RsaPrivateKeyBitSize(priv) != bits {
			t.Fatalf("inequal")
		}
	}

	f_test(1024)
	f_test(512)
	f_test(192)
}

func f_genBytes(n int) []byte {
	b := make([]byte, n)
	rn, err := rand.Read(b)
	if err != nil || rn != n {
		return nil
	}
	return b
}

func TestRsaEncrypt_PKCSv15(t *testing.T) {
	f_test := func(bits int) {
		privGen, _, err := RsaPrivateKeyGeneration(bits)
		if err != nil {
			t.Fatalf("key generate failed")
		}

		var out1, out2 []byte
		maxn := (bits+7)/8 - 11

		out1, err = RsaEncrypt_PKCSv15(privGen, f_genBytes(maxn))
		if err != nil {
			t.Fatalf("encrypt PKCSv1.5 failed, err[%v]", err)
		}

		out2, err = RsaEncrypt_PKCSv15(privGen, f_genBytes(maxn))
		if err != nil {
			t.Fatalf("encrypt PKCSv1.5 failed, err[%v]", err)
		}

		// out1 out2 由于加密过程中随机因子的存在，应该不一样
		if hex.EncodeToString(out1) == hex.EncodeToString(out2) {
			t.Fatalf("little probability to be the same ...")
		} else {
			fmt.Printf("bits[%d], maxn[%d], plainGen[%d], cipher[%d]\n", bits, maxn, maxn, len(out1))
		}

		_, err = RsaEncrypt_PKCSv15(privGen, f_genBytes(maxn+1))
		if err == nil {
			t.Fatalf("encrypt PKCSv1.5 should fail")
		}
	}

	f_test(256)
	f_test(1024)
	f_test(2048)
	f_test(2066)
}

func TestRsaDecrypt_PKCSv15(t *testing.T) {
	f_test := func(bits int) {
		privGen, _, err := RsaPrivateKeyGeneration(bits)
		if err != nil {
			t.Fatalf("key generate failed")
		}

		var cipher, plainGen, plainDecrypt []byte
		maxn := (bits+7)/8 - 11

		// encrypt
		plainGen = f_genBytes(maxn)
		cipher, err = RsaEncrypt_PKCSv15(privGen, plainGen)
		if err != nil {
			t.Fatalf("encrypt PKCSv1.5 failed, err[%v]", err)
		}

		// decrypt
		plainDecrypt, err = RsaDecrypt_PKCSv15(privGen, cipher)
		if err != nil {
			t.Fatalf("decrypt PKCSv1.5 failed, err[%v]", err)
		}

		if !bytes.Equal(plainGen, plainDecrypt) {
			t.Fatalf("not the same")
		} else {
			fmt.Printf("bits[%d], maxn[%d], plainGen[%d], cipher[%d]\n", bits, maxn, len(plainGen), len(cipher))
		}
	}

	f_test(256)
	f_test(512)
	f_test(1024)
	f_test(1066)
}

func TestRsaDecryptBlock_PKCSv15(t *testing.T) {
	f_test := func(bits int, plain []byte, bsize int) {
		maxn := (bits+7)/8 - 11
		fmt.Printf("bits[%d], maxn[%d], len(plain)[%d], bsize[%d]\n", bits, maxn, len(plain), bsize)
		
		privGen, _, err := RsaPrivateKeyGeneration(bits)
		if err != nil {
			t.Fatalf("key generate failed")
		}

		cipher, err := RsaEncryptBlock_PKCSv15(privGen, plain, bsize)
		if err != nil {
			t.Fatalf("block encrypt failed, err[%v]", err)
		}

		plainDecrypt, err := RsaDecryptBlock_PKCSv15(privGen, cipher)
		if err != nil {
			t.Fatalf("block decrypt failed, err[%v]", err)
		}

		if !bytes.Equal(plain, plainDecrypt) {
			t.Fatalf("not equal")
		}
	}

	f_test(256, f_genBytes(6), 21)
	f_test(256, f_genBytes(666), 21)
	f_test(256, f_genBytes(666), 1)
	f_test(256, f_genBytes(666), 12)
	
	f_test(512, f_genBytes(1666), 35)
	f_test(1024, f_genBytes(3666), 57)
	f_test(2048, f_genBytes(666), 245)
}
