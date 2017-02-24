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
		examplePrivPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAlzCD0hf0s/jFRshkfSvKLb1X4mEmizknrZwu5XLUc70v1L6V
3ImKPc54QOWc4kKdHIvpVNJ2QdhHeXit0LQgAWJmiayBu4RCNkX70WJ4yTuKbZPb
3/C0+pBSPhNeWKwaUrZWbDAv6WGKrb/cnWi21ooluxvZze9MvLuFBieLqi3k8y9E
qmKGWrROXg8FH9/QlzLCoFmu1GUnVPqIz9bEWBWfgjXdkUaaJ82kADdpURmYgsWS
rp4wPzjfrEaN7H4eztPMqA9eizoeZ0nGJ72WqfmL6XayBmC1Tg6cPWtC2NF1pBYy
NJ3DwC3gzLG7naOcW7WXNFchP/XHdtnqiEDFewIDAQABAoIBAFyaRZNQQvxcuhBh
u1MDmEEtwP+Se7Y4mrn2eK7nB4OgdAR9e3Lp93dl2Df/q3jWTj7m31Kp2e74lsar
CONVAGl4qM9YjtmY56kwck3MX6j5xA7byoe+eksiTI1i9Z2gRDs3HXYEicQLj5Je
erUbJyn+0Z9qLpy5HqpWvOKJJD1mD90tW73vO+bHE7p/o3pd9AQFzG+2V/rL7gO+
F6O8JQJxArjT3yN21dJKAPnRh1T5iwSURxZ9PasgVp3EYQOT9HXBya0/BVVxuoHq
8cn/1P8Bw13v3CwT70KO0zxmHKiqTiJRUDzCmH0Z0BEmn6BQ+gB883P3e3o25Upj
fYNQV8ECgYEAxdwGzTvTcN9sQAVPMTvmql5ZPNU7DcyYFWoyT9aIQUccQel/QQ3J
bQ+ybyjaS9QFHAd4PJbe8YjMxG8Z5P/0KCmvJ53sWyo4xvAcCQtMW9K+pe7ALROq
kIscE2wUtTUSdVvofiWkIeP+uu0gq84d7qxd0bKZB64aWb+GKTcaPOECgYEAw529
zzXON00ts250wG7DsmZstNs0hMVShvP79F2YNLITk4AXof8D6yZa0gq3+yr+6uNz
k/mua4mvF1Qw4hejbbv+AcS9EJpZ+60ZA35nRkoXOfxmzLVVZPyCpggeZ71NEWhy
J/aLPgC5thNcRsXBHWqF+h2QnnQkU6fgNtl70dsCgYBGsCMl87fI3amY/cybNGFm
gKq1FyEv/uZe0EAFUgn/+F3aFofGQBy0gCUpnZjP+oGQ0AJe8y/Xbx5pF6BStjcO
mkXfi4ZD08PRHzuE56pyK8q9EZ1K/Xm0hl6Tecu0Ka/cied4Gg6XpRL+yXUgrFT5
Tk9+eaY+ni7/3XMbCnqvQQKBgFxjnydDqV7zI7eQXrIYXnNe7s7IjVh7/cthZsl2
fxG8XYSXxhGr6UThu5limJyXJQj5Xjgwf9GomLqy99eBBJ4qYQCi1A0IaaF1ks/U
nqBTE/8+F6ttpaRpoqcaRIoInWKwauI3DnK9UvkM0dNXSStEiXylBA3imtmr+zjM
pS9rAoGAFwTWlN0PNVDdnsjsd6euWRjr8RGSfmaGNy/IghvrhEJ0dgMSKPs111Yo
vKpbOw7X6abkHg2YVzGJJjXe/1olNxg4c1l+GDCb6eRuw+LUaeTcbZwZLlUmVH0e
GBfiS4qj8OZhUDK024dKhnS6YpRDprjal44r5bzqmk20P7Upm9w=
-----END RSA PRIVATE KEY-----`

		examplePubPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlzCD0hf0s/jFRshkfSvK
Lb1X4mEmizknrZwu5XLUc70v1L6V3ImKPc54QOWc4kKdHIvpVNJ2QdhHeXit0LQg
AWJmiayBu4RCNkX70WJ4yTuKbZPb3/C0+pBSPhNeWKwaUrZWbDAv6WGKrb/cnWi2
1ooluxvZze9MvLuFBieLqi3k8y9EqmKGWrROXg8FH9/QlzLCoFmu1GUnVPqIz9bE
WBWfgjXdkUaaJ82kADdpURmYgsWSrp4wPzjfrEaN7H4eztPMqA9eizoeZ0nGJ72W
qfmL6XayBmC1Tg6cPWtC2NF1pBYyNJ3DwC3gzLG7naOcW7WXNFchP/XHdtnqiEDF
ewIDAQAB
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

	plain := []byte("jflajldfajsdlgjasldfjlajdfoqwealdfjlasjdlajglajflaisjdflaf")
	cipher, _ := RsaEncrypt_PKCSv15(pubGen, plain)

	plainGen, _ := RsaDecrypt_PKCSv15(priv, cipher)

	if !bytes.Equal(plain, plainGen) {
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
