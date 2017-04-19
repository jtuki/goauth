package rsa_auth

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
	PEM_BLOCK_TYPE_RSA_PUB  = "PUBLIC KEY"
)

// GenKey 根据指定的 bits 长度（如 256/1024/2048 等）生成私钥、公钥的对象。
func GenKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// EncodePrivToPEM 将指定的私钥对象 priv 按照指定的密码 pwd 生成密码保护的 pem 编码字节内容。
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
func EncodePrivToPEM(priv *rsa.PrivateKey, pwd string) ([]byte, error) {
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

// DecodePrivFromPEM 通过 PEM 编码字节内容 pemBlockBytes，生成私钥对象。如果没有密码，则 pwd 为空字符串。
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
func DecodePrivFromPEM(pemBlockBytes []byte, pwd string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
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

// EncodePubToPEM 将公钥信息编码成 PEM 格式编码的字节序列。
func EncodePubToPEM(pub *rsa.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  PEM_BLOCK_TYPE_RSA_PUB,
		Bytes: derBytes,
	}), nil
}

// DecodePubFromPEM 从公钥信息对应的 PEM 中解码出公钥信息。
func DecodePubFromPEM(pemBlockBytes []byte) (*rsa.PublicKey, error) {
	pb, _ := pem.Decode(pemBlockBytes)
	if pb == nil {
		return nil, errors.New("decode PEM block failed")
	}

	if pb.Type != PEM_BLOCK_TYPE_RSA_PUB {
		return nil, errors.New(fmt.Sprintf("invalid PEM block type[%s]", pb.Type))
	}

	pub, err := x509.ParsePKIXPublicKey(pb.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

// IsEqualPriv 判定两个 PrivateKey 对象是否相等。
func IsEqualPriv(priv1, priv2 *rsa.PrivateKey) bool {
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

// PrivKeySize 返回 RSA bit length，如 RSA 256 则返回 256。
func PrivKeySize(priv *rsa.PrivateKey) int {
	return priv.N.BitLen()
}
