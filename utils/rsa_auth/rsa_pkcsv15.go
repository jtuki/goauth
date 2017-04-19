package rsa_auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
)

// Encrypt_PKCSv15 对 plain 执行 PKCSv1.5 加密处理。
// 使用的是 pub 即公钥进行加密（公钥加密、私钥解密）。返回的是加密之后的值。
//
// Note:
//      1. 长度限制：len(plain) <= (bitsize(pub)+7)/8 - 11
//      比如 RSA256 而言，plain 的长度不得超过 (256+7)/8-11=32-11=21 字节。
//      同理，对于 RSA1024 而言，plain 的长度不得超过 (1024+7)/8-11=128-11=117 字节。
//      2. 对同一个 plain 的多次加密结果，由于加密过程中随机因子的存在（rand.Reader），一般都不一样。
func Encrypt_PKCSv15(pub *rsa.PublicKey, plain []byte) ([]byte, error) {
	out, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plain)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// Decrypt_PKCSv15 对 cipher 执行 PKCSv1.5 解密处理。
// 返回的是解密之后的值。
func Decrypt_PKCSv15(priv *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, priv, cipher)
}

// EncryptBlock_PKCSv15 对 plain 执行分块加密的处理，分块长度是 bsize。
// 使用的是 priv.PublicKey 即公钥进行加密（公钥加密、私钥解密）。返回的是加密之后的值。
func EncryptBlock_PKCSv15(priv *rsa.PrivateKey, plain []byte, bsize int) ([]byte, error) {
	maxn := (PrivKeySize(priv)+7)/8 - 11
	if bsize > maxn {
		return nil, errors.New(fmt.Sprintf("invalid block size[%d], maxn[%d]", bsize, maxn))
	}

	if len(plain) <= maxn {
		return Encrypt_PKCSv15(&priv.PublicKey, plain)
	}

	cipher := make([]byte, (len(plain)+bsize-1)/bsize*(maxn+11))
	// fmt.Printf("len(plain)[%d], len(cipher)[%d]\n", len(plain), len(cipher))

	for n := 0; n < len(plain); n += bsize {
		end := n + bsize
		if end > len(plain) {
			end = len(plain)
		}

		// cipher block
		cb, err := Encrypt_PKCSv15(&priv.PublicKey, plain[n:end])
		if err != nil {
			return nil, err
		}

		// fmt.Printf("n[%d], end[%d], len(cb)[%d], cipherOffset[%d]\n", n, end, len(cb), (n/bsize)*(maxn+11))
		copy(cipher[(n/bsize)*(maxn+11):], cb)
	}

	return cipher, nil
}

// DecryptBlock_PKCSv15 对 cipher 执行 PKCSv1.5 解密处理。
// 返回的是解密之后的值。
func DecryptBlock_PKCSv15(priv *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	maxn := (PrivKeySize(priv)+7)/8 - 11
	// each encrypted block's size
	bsize := maxn + 11

	if len(cipher)%bsize != 0 {
		return nil, errors.New(fmt.Sprintf("invalid cipher content length, bits[%d], len(cipher)[%d]", PrivKeySize(priv), len(cipher)))
	}

	if len(cipher) <= bsize {
		return Decrypt_PKCSv15(priv, cipher)
	}

	plain := make([]byte, 0)
	for n := 0; n < len(cipher); n += bsize {
		end := n + bsize
		if end > len(cipher) {
			end = len(cipher)
		}
		pt, err := Decrypt_PKCSv15(priv, cipher[n:end])
		if err != nil {
			return nil, err
		}
		plain = append(plain, pt...)
	}

	return plain, nil
}
