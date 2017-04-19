package rsa_auth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

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
		privGen, _, err := GenKey(bits)
		if err != nil {
			t.Fatalf("key generate failed")
		}

		var out1, out2 []byte
		maxn := (bits+7)/8 - 11

		out1, err = Encrypt_PKCSv15(&privGen.PublicKey, f_genBytes(maxn))
		if err != nil {
			t.Fatalf("encrypt PKCSv1.5 failed, err[%v]", err)
		}

		out2, err = Encrypt_PKCSv15(&privGen.PublicKey, f_genBytes(maxn))
		if err != nil {
			t.Fatalf("encrypt PKCSv1.5 failed, err[%v]", err)
		}

		// out1 out2 由于加密过程中随机因子的存在，应该不一样
		if hex.EncodeToString(out1) == hex.EncodeToString(out2) {
			t.Fatalf("little probability to be the same ...")
		} else {
			fmt.Printf("bits[%d], maxn[%d], plainGen[%d], cipher[%d]\n", bits, maxn, maxn, len(out1))
		}

		_, err = Encrypt_PKCSv15(&privGen.PublicKey, f_genBytes(maxn+1))
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
		privGen, _, err := GenKey(bits)
		if err != nil {
			t.Fatalf("key generate failed")
		}

		var cipher, plainGen, plainDecrypt []byte
		maxn := (bits+7)/8 - 11

		// encrypt
		plainGen = f_genBytes(maxn)
		cipher, err = Encrypt_PKCSv15(&privGen.PublicKey, plainGen)
		if err != nil {
			t.Fatalf("encrypt PKCSv1.5 failed, err[%v]", err)
		}

		// decrypt
		plainDecrypt, err = Decrypt_PKCSv15(privGen, cipher)
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

		privGen, _, err := GenKey(bits)
		if err != nil {
			t.Fatalf("key generate failed")
		}

		cipher, err := EncryptBlock_PKCSv15(privGen, plain, bsize)
		if err != nil {
			t.Fatalf("block encrypt failed, err[%v]", err)
		}

		plainDecrypt, err := DecryptBlock_PKCSv15(privGen, cipher)
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
