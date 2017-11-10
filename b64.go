// Copyright 2016 Mark K Mueller github.com/mkmueller
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes256

import (
    "encoding/base64"
)



// EncryptB64 accepts a plaintext string, encrypts it, then returns a base-64 encoded string.
//
// Usage:   ciphertext, err := EncryptB64( plaintext )
//
func (ci Cipher) EncryptB64 (plaintext string) (b64str string, err error) {
    ciphertext_bytes, err := ci.Encrypt(plaintext)
    if err != nil {
        return
	}
    b64str = base64.StdEncoding.EncodeToString(ciphertext_bytes)
    return
}



// DecryptB64 accepts a base-64 encoded string, encrypts it, then returns a plaintext string.
//
// Usage:   plaintext, err := DecryptB64( ciphertext )
//
func (ci Cipher) DecryptB64 (b64str string) (plaintext string, err error) {
    bytes, err := base64.StdEncoding.DecodeString(b64str)
    if err != nil {
        return
	}
    plaintext, err = ci.Decrypt(bytes)
    return
}





//eof//