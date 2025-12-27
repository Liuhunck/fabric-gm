/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/rand"

	"github.com/hyperledger/fabric/bccsp"
)

type sm2Signer struct{}

func (*sm2Signer) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return k.(*sm2PrivateKey).privKey.Sign(rand.Reader, msg, nil)
}

type sm2PrivateKeyVerifier struct{}

func (*sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	pub := &k.(*sm2PrivateKey).privKey.PublicKey
	return pub.Verify(msg, signature), nil
}

type sm2PublicKeyVerifier struct{}

func (*sm2PublicKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	pub := k.(*sm2PublicKey).pubKey
	return pub.Verify(msg, signature), nil
}
