package aes256_test

import (
	"fmt"
	"github.com/mkmueller/aes256"
)

var err error
var	txt []byte = []byte("There are three great virtues of a programmer; Laziness, Impatience and Hubris")
var aes *aes256.Cipher
var ctxt []byte
var ptxt []byte
var base64_str string

func init () {

	aes, err = aes256.New("carfard")
	if err != nil { panic(err.Error()) }
	ctxt, _ = aes.Encrypt(txt)
	base64_str, _ = aes.EncryptB64(txt)

}

func ExampleNew () {

	aes, err = aes256.New("carfard")
	if err != nil { panic(err.Error()) }

}

func ExampleCipher_Decrypt () {

	aes, err := aes256.New("carfard")
	if err != nil { panic(err.Error()) }
	ptxt, err = aes.Decrypt(ctxt)

}

func ExampleCipher_Encrypt () {

	txt = []byte("There are three great virtues of a programmer; Laziness, Impatience and Hubris")
	aes, err = aes256.New("carfard")
	if err != nil { panic(err.Error()) }
	ctxt, err = aes.Encrypt(txt)

}

func ExampleCipher_EncryptB64 () {

	aes, err = aes256.New("carfard")
	if err != nil { panic(err.Error()) }
	base64_str, err = aes.EncryptB64(txt)

}

func ExampleCipher_DecryptB64 () {

	aes, err := aes256.New("carfard")
	if err != nil { panic(err.Error()) }
	ptxt, err = aes.DecryptB64(base64_str)

}

func ExampleDecrypt () {

	ptxt, err := aes256.Decrypt("carfard", ctxt)
	if err != nil { panic(err.Error()) }
	fmt.Print(string(ptxt))
	// Output:
	// There are three great virtues of a programmer; Laziness, Impatience and Hubris

}

func ExampleDecryptB64 () {

	ptxt, err = aes256.DecryptB64("carfard", base64_str)
	if err != nil { panic(err.Error()) }

}

func ExampleEncrypt () {

	ctxt, err = aes256.Encrypt("carfard", txt)
	if err != nil { panic(err.Error()) }

}

func ExampleEncryptB64 () {

	base64_str, err = aes256.EncryptB64("carfard", txt)
	if err != nil { panic(err.Error()) }

}
