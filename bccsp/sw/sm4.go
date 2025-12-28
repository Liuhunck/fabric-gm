/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm4"
)

func pkcs7PaddingWithBlockSize(blockSize int, src []byte) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPaddingWithBlockSize(blockSize int, src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("Invalid pkcs7 padding (empty)")
	}
	unpadding := int(src[length-1])

	if unpadding > blockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > blockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func sm4CBCEncrypt(key, s []byte) ([]byte, error) {
	return sm4CBCEncryptWithRand(rand.Reader, key, s)
}

func sm4CBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, sm4.BlockSize+len(s))
	iv := ciphertext[:sm4.BlockSize]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:], s)

	return ciphertext, nil
}

func sm4CBCEncryptWithIV(iv []byte, key, s []byte) ([]byte, error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	if len(iv) != sm4.BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, sm4.BlockSize+len(s))
	copy(ciphertext[:sm4.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:], s)

	return ciphertext, nil
}

func sm4CBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < sm4.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}
	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	if len(src)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(src, src)

	return src, nil
}

// SM4CBCPKCS7Encrypt combines SM4-CBC encryption and PKCS7 padding.
func SM4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	tmp := pkcs7PaddingWithBlockSize(sm4.BlockSize, src)
	return sm4CBCEncrypt(key, tmp)
}

// SM4CBCPKCS7EncryptWithRand combines SM4-CBC encryption and PKCS7 padding using the passed PRNG.
func SM4CBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	tmp := pkcs7PaddingWithBlockSize(sm4.BlockSize, src)
	return sm4CBCEncryptWithRand(prng, key, tmp)
}

// SM4CBCPKCS7EncryptWithIV combines SM4-CBC encryption and PKCS7 padding using the passed IV.
func SM4CBCPKCS7EncryptWithIV(iv []byte, key, src []byte) ([]byte, error) {
	tmp := pkcs7PaddingWithBlockSize(sm4.BlockSize, src)
	return sm4CBCEncryptWithIV(iv, key, tmp)
}

// SM4CBCPKCS7Decrypt combines SM4-CBC decryption and PKCS7 unpadding.
func SM4CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	pt, err := sm4CBCDecrypt(key, src)
	if err != nil {
		return nil, err
	}
	return pkcs7UnPaddingWithBlockSize(sm4.BlockSize, pt)
}

type sm4cbcpkcs7Encryptor struct{}

func (e *sm4cbcpkcs7Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return SM4CBCPKCS7EncryptWithIV(o.IV, k.(*sm4PrivateKey).privKey, plaintext)
		} else if o.PRNG != nil {
			return SM4CBCPKCS7EncryptWithRand(o.PRNG, k.(*sm4PrivateKey).privKey, plaintext)
		}
		return SM4CBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
	case bccsp.SM4CBCPKCS7ModeOpts:
		return e.Encrypt(k, plaintext, &o)
	case *bccsp.AESCBCPKCS7ModeOpts:
		// Allow reuse of AES mode opts for SM4 since CBC+PKCS7 options are identical.
		sm4opts := &bccsp.SM4CBCPKCS7ModeOpts{IV: o.IV, PRNG: o.PRNG}
		return e.Encrypt(k, plaintext, sm4opts)
	case bccsp.AESCBCPKCS7ModeOpts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

type sm4cbcpkcs7Decryptor struct{}

func (*sm4cbcpkcs7Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	switch opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts, bccsp.SM4CBCPKCS7ModeOpts:
		return SM4CBCPKCS7Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
	case *bccsp.AESCBCPKCS7ModeOpts, bccsp.AESCBCPKCS7ModeOpts:
		return SM4CBCPKCS7Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}
