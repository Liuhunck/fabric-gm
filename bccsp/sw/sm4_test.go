/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"bytes"
	"testing"

	"github.com/hyperledger/fabric/bccsp"
)

func TestSM4CBCPKCS7EncryptDecrypt(t *testing.T) {
	key, err := GetRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	msg := []byte("Hello World")
	ct, err := SM4CBCPKCS7Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}
	pt, err := SM4CBCPKCS7Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatalf("Decrypted plaintext differs. [%x][%x]", msg, pt)
	}
}

func TestSM4EncryptorDecryptor(t *testing.T) {
	key, err := GetRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	k := &sm4PrivateKey{privKey: key, exportable: false}
	encryptor := &sm4cbcpkcs7Encryptor{}
	decryptor := &sm4cbcpkcs7Decryptor{}

	msg := []byte("Hello World")
	ct, err := encryptor.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}
	pt, err := decryptor.Decrypt(k, ct, &bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if !bytes.Equal(msg, pt) {
		t.Fatalf("Decrypted plaintext differs. [%x][%x]", msg, pt)
	}
}
