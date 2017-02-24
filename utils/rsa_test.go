package utils

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"strings"
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

// encode to and decode from PEM
func TestRsaPublicKeyPEM(t *testing.T) {
	const (
		// openssl genrsa -out private.pem 512
		examplePrivPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALYGcL/naWtMnq6n6AKoRWfAmeyoVKe7PDe3fR4S1c6qZTbbHNWD
k9SeqdJZ5g3YPU3PVC7a0Egz4A3a2Cod8LsCAwEAAQJAaPtR7/xhmpb4Njd04oN2
dB5rKEj1ej/MvT3AlaW7VpOK0uZS7NGuyVTXm52xTBrJaZU/QuxsvKPmUm42Y50O
0QIhAODYCVFAVuZR3x3taI4YNTvY0MzbEfT/pQfSVUTOSqGFAiEAzz97BdJJ3xTC
fjk+CHmLSlt/LgvmVZSLhPp8PLHNvT8CIQDNN2EJr9eg0Aj8n7tWNfIgdXvd/fUd
0FcoFGmPK1oioQIgN3uOKtPOVPuQygv3EHvBj4mJNcGXy2d2JoaMhg8vvi8CIA4l
Q8+9vxL3DqsC26N0/2vZAp8mTEWgH+VXbOtmiM52
-----END RSA PRIVATE KEY-----`

		// openssl rsa -in private.pem -pubout -out public.pem
		examplePubPEM = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALYGcL/naWtMnq6n6AKoRWfAmeyoVKe7
PDe3fR4S1c6qZTbbHNWDk9SeqdJZ5g3YPU3PVC7a0Egz4A3a2Cod8LsCAwEAAQ==
-----END PUBLIC KEY-----`
	)

	priv, _, err := RsaPrivateKeyDecodeFromPEM([]byte(examplePrivPEM), "")
	if err != nil {
		t.Fatalf("decode from private key failed")
	}

	pemPublic, err := RsaPublicKeyEncodeToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encode to pem failed")
	}

	if strings.Index(string(pemPublic), examplePubPEM) == -1 {
		fmt.Println(string(pemPublic))
		t.Fatalf("not equal")
	}

	// 尝试着进行加密解密操作
	pubGen, err := RsaPublicKeyDecodeFromPEM([]byte(examplePubPEM))
	if err != nil {
		t.Fatalf("decode from pem public key failed")
	}

	plain := []byte("jflajldfajsdlgjaslasdfadgad")
	cipher, err := RsaEncrypt_PKCSv15(pubGen, plain)
	if err != nil {
		t.Fatalf("encrypt to cipher failed, err[%v]", err)
	}

	plainGen, err := RsaDecrypt_PKCSv15(priv, cipher)
	if err != nil {
		t.Fatalf("decrypt to plainGen failed")
	}

	if !bytes.Equal(plain, plainGen) {
		fmt.Println(string(plainGen))
		t.Fatal("not equal")
	}
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
