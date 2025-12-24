/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

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

package bccsp

// GMSM2KeyGenOpts contains options for GMSM2 key generation.
type GMSM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *GMSM2KeyGenOpts) Algorithm() string {
	return GMSM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *GMSM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM4KeyGenOpts contains options for GMSM4 key generation.
type GMSM4KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *GMSM4KeyGenOpts) Algorithm() string {
	return GMSM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *GMSM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM4ImportKeyOpts contains options for importing GMSM4 keys.
type GMSM4ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *GMSM4ImportKeyOpts) Algorithm() string {
	return GMSM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *GMSM4ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM2PrivateKeyImportOpts contains options for importing GMSM2 private keys.
type GMSM2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *GMSM2PrivateKeyImportOpts) Algorithm() string {
	return GMSM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *GMSM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM2PublicKeyImportOpts contains options for importing GMSM2 public keys.
type GMSM2PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *GMSM2PublicKeyImportOpts) Algorithm() string {
	return GMSM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *GMSM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM3Opts contains options for GMSM3 hash.
type GMSM3Opts struct{}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *GMSM3Opts) Algorithm() string {
	return GMSM3
}
