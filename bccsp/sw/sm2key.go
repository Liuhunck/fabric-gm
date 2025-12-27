/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

type sm2PrivateKey struct {
	privKey *sm2.PrivateKey
}

// Bytes converts this key to its byte representation, if this operation is allowed.
func (k *sm2PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *sm2PrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (k *sm2PrivateKey) Symmetric() bool { return false }
func (k *sm2PrivateKey) Private() bool   { return true }

func (k *sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &sm2PublicKey{pubKey: &k.privKey.PublicKey}, nil
}

type sm2PublicKey struct {
	pubKey *sm2.PublicKey
}

func (k *sm2PublicKey) Bytes() ([]byte, error) {
	raw, err := gmx509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return raw, nil
}

func (k *sm2PublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (k *sm2PublicKey) Symmetric() bool { return false }
func (k *sm2PublicKey) Private() bool   { return false }
func (k *sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
