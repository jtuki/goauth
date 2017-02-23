package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

const (
	PEM_BLOCK_TYPE_RSA_PRIV = "RSA PRIVATE KEY"
)

// RsaPrivateKeyGeneration 根据指定的 bits 长度（如 256/1024/2048 等）生成私钥、公钥的对象。
func RsaPrivateKeyGeneration(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// RsaPrivateKeyEncodeToPEM 将指定的私钥对象 priv 按照指定的密码 pwd 生成密码保护的 pem 编码字节内容。
//
// 编码之后的结果：
//      -----BEGIN Type-----
//      Headers
//      base64-encoded Bytes
//      -----END Type-----
// 其中 Headers 是可能为空的 key: value 键值对。
//
// eg.
//      -----BEGIN RSA PRIVATE KEY-----
//      Proc-Type: 4,ENCRYPTED
//      DEK-Info: AES-256-CBC,dcf19de3e667684239652876c0aa2186
//
//      xohwTCNrsBmq+lwJgQG2d8gGGXeTtER/wKFbuioCy6DKiS9mb7YODCSFiUcWzTBP
//      Q1aRFNsQg0f/PZ3HUpZQa7CFfgv7cfQAHJ3MrXsuxa8J3o5GZc3/swjejYj7FG+X
//      t+XMGPsxvQ/IzcqnbFr8HnT5kUjnJnvRBvMlkSCTZkoSvHLZQypI833a4veUBLGP
//      xmH13k/U6Tf3Y/ENLPVh1jc/asKUN7kbBhtxg1wT1m4=
//      -----END RSA PRIVATE KEY-----
//
// Note:
//      1. http://stackoverflow.com/questions/37316370/how-create-rsa-private-key-with-passphrase-in-golang
//      2. 如果无需进行加密处理，pwd 为空即可。
func RsaPrivateKeyEncodeToPEM(priv *rsa.PrivateKey, pwd string) ([]byte, error) {
	var block *pem.Block
	block = &pem.Block{
		Type:  PEM_BLOCK_TYPE_RSA_PRIV,
		Bytes: x509.MarshalPKCS1PrivateKey(priv), // ASN.1 DER encoded form
	}

	// encrypt
	if pwd != "" {
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(pwd), x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	}

	return pem.EncodeToMemory(block), nil
}

// RsaPrivateKeyDecodeFromPEM 通过 PEM 编码字节内容 pemBlockBytes，生成私钥对象。如果没有密码，则 pwd 为空字符串。
// eg.
//      -----BEGIN RSA PRIVATE KEY-----
//      Proc-Type: 4,ENCRYPTED
//      DEK-Info: AES-256-CBC,dcf19de3e667684239652876c0aa2186
//
//      xohwTCNrsBmq+lwJgQG2d8gGGXeTtER/wKFbuioCy6DKiS9mb7YODCSFiUcWzTBP
//      Q1aRFNsQg0f/PZ3HUpZQa7CFfgv7cfQAHJ3MrXsuxa8J3o5GZc3/swjejYj7FG+X
//      t+XMGPsxvQ/IzcqnbFr8HnT5kUjnJnvRBvMlkSCTZkoSvHLZQypI833a4veUBLGP
//      xmH13k/U6Tf3Y/ENLPVh1jc/asKUN7kbBhtxg1wT1m4=
//      -----END RSA PRIVATE KEY-----
func RsaPrivateKeyDecodeFromPEM(pemBlockBytes []byte, pwd string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pb, _ := pem.Decode(pemBlockBytes)
	if pb == nil {
		return nil, nil, errors.New("decode PEM block failed")
	}

	if pb.Type != PEM_BLOCK_TYPE_RSA_PRIV {
		return nil, nil, errors.New(fmt.Sprintf("invalid PEM block type[%s]", pb.Type))
	}

	// decrypt
	if pwd != "" {
		derBytes, err := x509.DecryptPEMBlock(pb, []byte(pwd))
		if err != nil {
			return nil, nil, err
		}
		pb.Bytes = derBytes
	}

	priv, err := x509.ParsePKCS1PrivateKey(pb.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return priv, &priv.PublicKey, nil
}

// RsaPrivateKeyEqual 判定两个 PrivateKey 对象是否相等。
func RsaPrivateKeyEqual(priv1, priv2 *rsa.PrivateKey) bool {
	if priv1.E != priv2.E {
		return false
	}

	// big int x == y?
	f_bigIntEqual := func(x *big.Int, y *big.Int) bool {
		var z big.Int
		if z.Sub(priv1.N, priv2.N).Int64() != 0 {
			return false
		}
		return true
	}

	if !f_bigIntEqual(priv1.N, priv2.N) || !f_bigIntEqual(priv1.D, priv2.D) {
		return false
	}

	return true
}

// RsaPrivateKeyBitSize 返回 RSA bit length，如 RSA 256 则返回 256。
func RsaPrivateKeyBitSize(priv *rsa.PrivateKey) int {
	return priv.N.BitLen()
}

// RsaEncrypt_PKCSv15 对 plain 执行 PKCSv1.5 加密处理。
// 使用的是 priv.PublicKey 即公钥进行加密（公钥加密、私钥解密）。返回的是加密之后的值。
//
// Note:
//      1. 长度限制：len(plain) <= (bitsize(priv)+7)/8 - 11
//      比如 RSA256 而言，plain 的长度不得超过 (256+7)/8-11=32-11=21 字节。
//      同理，对于 RSA1024 而言，plain 的长度不得超过 (1024+7)/8-11=128-11=117 字节。
//      2. 对同一个 plain 的多次加密结果，由于加密过程中随机因子的存在（rand.Reader），一般都不一样。
func RsaEncrypt_PKCSv15(priv *rsa.PrivateKey, plain []byte) ([]byte, error) {
	out, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, plain)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// RsaDecrypt_PKCSv15 对 cipher 执行 PKCSv1.5 解密处理。
// 返回的是解密之后的值。
func RsaDecrypt_PKCSv15(priv *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, priv, cipher)
}

// RsaEncryptBlock_PKCSv15 对 plain 执行分块加密的处理，分块长度是 bsize。
// 使用的是 priv.PublicKey 即公钥进行加密（公钥加密、私钥解密）。返回的是加密之后的值。
func RsaEncryptBlock_PKCSv15(priv *rsa.PrivateKey, plain []byte, bsize int) ([]byte, error) {
	maxn := (RsaPrivateKeyBitSize(priv)+7)/8 - 11
	if bsize > maxn {
		return nil, errors.New(fmt.Sprintf("invalid block size[%d], maxn[%d]", bsize, maxn))
	}
	
	if len(plain) <= maxn {
		return RsaEncrypt_PKCSv15(priv, plain)
	}

	cipher := make([]byte, (len(plain)+bsize-1)/bsize*(maxn+11))
	// fmt.Printf("len(plain)[%d], len(cipher)[%d]\n", len(plain), len(cipher))

	for n := 0; n < len(plain); n += bsize {
		end := n + bsize
		if end > len(plain) {
			end = len(plain)
		}

		// cipher block
		cb, err := RsaEncrypt_PKCSv15(priv, plain[n:end])
		if err != nil {
			return nil, err
		}

		// fmt.Printf("n[%d], end[%d], len(cb)[%d], cipherOffset[%d]\n", n, end, len(cb), (n/bsize)*(maxn+11))
		copy(cipher[(n/bsize)*(maxn+11):], cb)
	}

	return cipher, nil
}

// RsaDecryptBlock_PKCSv15 对 cipher 执行 PKCSv1.5 解密处理。
// 返回的是解密之后的值。
func RsaDecryptBlock_PKCSv15(priv *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	maxn := (RsaPrivateKeyBitSize(priv)+7)/8 - 11
	// each encrypted block's size
	bsize := maxn + 11

	if len(cipher)%bsize != 0 {
		return nil, errors.New(fmt.Sprintf("invalid cipher content length, bits[%d], len(cipher)[%d]", RsaPrivateKeyBitSize(priv), len(cipher)))
	}

	if len(cipher) <= bsize {
		return RsaDecrypt_PKCSv15(priv, cipher)
	}

	plain := make([]byte, 0)
	for n := 0; n < len(cipher); n += bsize {
		end := n + bsize
		if end > len(cipher) {
			end = len(cipher)
		}
		pt, err := RsaDecrypt_PKCSv15(priv, cipher[n:end])
		if err != nil {
			return nil, err
		}
		plain = append(plain, pt...)
	}

	return plain, nil
}
