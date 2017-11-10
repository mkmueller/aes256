// Copyright 2016 Mark K Mueller github.com/mkmueller
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The aes256 package provides a wrapper for the standard aes package provided
// by The Go Authors with a couple added features.  Implements a 256 bit key
// length and the GCM cipher.  Your key may be a string of any length with an
// optional hash iteration value.  The encrypted output may be a byte slice or
// a base-64 encoded string.
//
package aes256

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/rand"
	"crypto/aes"
	"errors"
	"io"
)


const (
    Version       = "1.01"

    // keylen must be 16, 24, or 32
    // 16=AES-128, 24=AES-192, 32=AES-256
    keylen         = 32

    // ivLength must be 12
    ivLength       = 12

)

type Cipher struct {
    key []byte
}

var (
	errZeroLen = errors.New("aes256: Zero length key")
	errCtShort = errors.New("aes256: Ciphertext too short")
)

// New returns a new Cipher instance.  The supplied key will be rehashed the
// number of times indicated by the optional rehash argument.
//
// Usage:   mycipher, err := New( key [, rehash] )
//
func New (key string, rehash ...uint) (Cipher, error) {

    var ci Cipher
    var err error

    // zero length key not allowed
    if len(key) == 0 {
        return ci, errZeroLen
    }

    // hash the key once
    k := sha256.Sum256([]byte(key))
    ci.key = k[0:]

    // If the key rehash argument is defined, rehash the key
    if len(rehash) > 0 {
        for n := rehash[0]; n > 0; n-- {
            k = sha256.Sum256(ci.key)
            ci.key = k[0:]
        }
    }

    ci.key = k[:keylen]
    return ci, err
}




// Encrypt accepts a plaintext string and returns an encrypted byte array.
// The initialization vector will be included in the first 12 bytes of the returned array.
//
// Usage:   cipherbytes, err := Encrypt( plaintext )
//
func (ci Cipher) Encrypt (plaintext string) (bytes []byte, err error) {

    // create a new cipher block
	block, err := aes.NewCipher(ci.key)
	if err != nil {
        return
	}

    // create iv
	iv := make([]byte, ivLength)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
        return
	}

    // create a new cgm cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
        return
	}

    // create ciphertext
	ctext := gcm.Seal(nil, iv, []byte(plaintext), nil)
    bytes = make([]byte, ivLength + len(ctext))

    // assemble the byte array
    copy(bytes, iv)
    copy(bytes[ivLength:], ctext)

    return
}



// Decrypt accepts a byte array, decrpyts it, then returns a plaintext string.
// The initialization vector must will be included in the first 12 bytes of the array.
//
// Usage:   plaintext, err := Decrypt( cipherbytes )
//
func (ci Cipher) Decrypt ( ciphertext []byte ) (plaintext string, err error) {

    if len(ciphertext) <= ivLength {
        return "", errCtShort
    }

    // split iv and ciphertext
    iv := ciphertext[0:ivLength]
    ct_bytes := ciphertext[ivLength:]

    // create a new cipher block
	cblock, err := aes.NewCipher(ci.key)
	if err != nil {
        return
	}

    // create a new cgm cipher
	gcm, err := cipher.NewGCM(cblock)
	if err != nil {
        return
	}

    // decrypt ciphertext
	pt, err := gcm.Open(nil, iv, ct_bytes, nil)
	if err != nil {
        return
	}

    plaintext = string(pt)
    return
}

//eof//