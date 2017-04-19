package rsa_sign

import (
	"crypto/rsa"
	"crypto"
	"crypto/rand"
	"errors"
)

// GenSign 生成数字签名。
//
// @param hash - 安全哈希算法，如 crypto.SHA1 crypto.SHA256 等等。
// @param priv - 私钥。
// @param saltLength - 加盐的长度。rsa.PSSSaltLengthAuto(0) || rsa.PSSSaltLengthEqualsHash(-1) || 指定固定长度（推荐）。
// @param content - 待签名的内容字节序列。
//
// @return 签名（signature）或者发生的错误（err）。
func GenSign(chash crypto.Hash, priv *rsa.PrivateKey, saltLength int, content []byte) (signature []byte, err error) {
	var opts rsa.PSSOptions
	if saltLength == rsa.PSSSaltLengthAuto || saltLength == rsa.PSSSaltLengthEqualsHash || saltLength > 0 {
		opts.SaltLength = saltLength
	} else {
		return nil, errors.New("invalid param saltLength")
	}
	
	h := chash.New()
	if _, err = h.Write(content); err != nil {
		return
	}

	hashed := h.Sum(nil)
	signature, err = rsa.SignPSS(rand.Reader, priv, chash, hashed, &opts)
	return
}

// VerifySign 验证数字签名的正确性。
//
// @param hash - 安全哈希算法，如 crypto.SHA1 crypto.SHA256 等等。
// @param pub - 公钥。
// @param saltLength - 加盐的长度。rsa.PSSSaltLengthAuto(0) || rsa.PSSSaltLengthEqualsHash(-1) || 指定固定长度（推荐）。
// @param content - 待签名的内容字节序列。
// @param signature - 签名计算后的结果。
//
// @return 如果验证ok则是nil，否则是对应的错误。
func VerifySign(chash crypto.Hash, pub *rsa.PublicKey, saltLength int, content []byte, signature []byte) error {
	var opts rsa.PSSOptions
	if saltLength == rsa.PSSSaltLengthAuto || saltLength == rsa.PSSSaltLengthEqualsHash || saltLength > 0 {
		opts.SaltLength = saltLength
	} else {
		return errors.New("invalid param saltLength")
	}
	
	h := chash.New()
	if _, err := h.Write(content); err != nil {
		return err
	}

	hashed := h.Sum(nil)
	return rsa.VerifyPSS(pub, chash, hashed, signature, &opts)
}