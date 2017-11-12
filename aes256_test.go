package aes256_test

import (
	"sync"
    "testing"
	"github.com/mkmueller/aes256"
    . "github.com/smartystreets/goconvey/convey"
)


// set the plaintext and key variables for use in the test routines
var plaintext []byte = []byte("The thing about space is that it's black, and the thing "+
"about a black hole is that it's black.  So how are you supposed to see it?");
var bogus_data []byte = []byte{0x5f, 0x2e, 0x00, 0xfa, 0xe9}
var key string       = "12345678901234567890"

func Test_10_New ( t *testing.T ) {


    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("New will accept a key of any size:", t, func() {

	    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
	    Convey("\nGiven a key of 1 byte", func() {
	        _, err := aes256.New("0")
	        So(err,  ShouldBeNil)
	    })

        //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
        Convey("\nGiven a really huge key", func() {
			fatkey := string(make([]byte, 999999))
            _, err := aes256.New(fatkey)
            So(err,  ShouldBeNil)
        })

    })

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("\nGiven a rehash value of 1,000,000", t, func() {
        _, err := aes256.New(key, 1000000)
        So(err,  ShouldBeNil)
    })


}

func Test_20_Encrypt_Decrypt ( t *testing.T ) {

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the Encrypt and Decrypt methods:", t, func() {

	    aes, err := aes256.New(key)
	    So(err,  ShouldBeNil)

	    ciphertextArray, err := aes.Encrypt(plaintext)
	    So(err,  ShouldBeNil)

	    deciphered_text, err := aes.Decrypt(ciphertextArray)
	    So(err,  ShouldBeNil)

	    Convey("The deciphered text should equal the original plain text", func() {
	        So(deciphered_text, ShouldResemble, plaintext)
	    })
    })

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the Encrypt and Decrypt functions:", t, func() {

	    ciphertextArray, err := aes256.Encrypt(key, plaintext)
	    So(err,  ShouldBeNil)

	    deciphered_text, err := aes256.Decrypt(key, ciphertextArray)
	    So(err,  ShouldBeNil)

	    Convey("The deciphered text should equal the original plain text", func() {
	        So(deciphered_text, ShouldResemble, plaintext)
	    })
    })

}


func Test_30_EncryptB64 ( t *testing.T ) {

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the EncryptB64 method (encrypt directly to a base-64 string):", t, func() {

        aes, err := aes256.New(key)
        So(err,  ShouldBeNil)

        ciphertextB64, err := aes.EncryptB64(plaintext)
        So(err,  ShouldBeNil)

        Convey("The length of the ciphertext should be greater than 32 bytes", func() {
            So(len(ciphertextB64),  ShouldBeGreaterThan, 32)
        })

    })

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the DecryptB64 method (decrypt from a base-64 string):", t, func() {

        aes, err := aes256.New(key)
        So(err,  ShouldBeNil)

        ciphertextB64, err := aes.EncryptB64(plaintext)
        So(err,  ShouldBeNil)

        deciphered_text, err := aes.DecryptB64(ciphertextB64)
        So(err,  ShouldBeNil)
        So(deciphered_text,  ShouldResemble, plaintext)

    })

}


func Test_35_Encrypt_GoRoutines ( t *testing.T ) {

	var wg sync.WaitGroup

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //

	for i := 0; i < 100; i++ {

		wg.Add(1)

		go func(wg *sync.WaitGroup){
			defer wg.Done()

	        aes, err := aes256.New(key)
			if err != nil { t.Fatal(err.Error()) }

	        ciphertext, err := aes.Encrypt(plaintext)
			if err != nil { t.Fatal(err.Error()) }

	        _, err = aes.Decrypt(ciphertext)
			if err != nil { t.Fatal(err.Error()) }


		}(&wg)

		wg.Wait()

	}


}

func Test_40_ForceErrors ( t *testing.T ) {

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Force a few errors:", t, func() {

        aes, err := aes256.New("")

	    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
	    Convey("\nGiven an empty key, we should expect an error", func() {
	        So(err, ShouldNotBeNil)
	    })

        Convey("Attempt Encrypt method on our empty Cipher object", func() {
            _, err := aes.Encrypt(plaintext)
            So(err, ShouldNotBeNil)
	    })

        Convey("Attempt Decrypt method on our empty Cipher object", func() {
            _, err := aes.Decrypt(plaintext)
            So(err, ShouldNotBeNil)
	    })

	})


    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the Decrypt method on bogus data:", t, func() {
        aes, err := aes256.New(key)
        So(err,  ShouldBeNil)

        Convey("Should return an error", func() {
	        deciphered_text, err := aes.Decrypt(bogus_data)
	        So(err,  ShouldNotBeNil)
            So(deciphered_text,  ShouldBeNil)
        })

    })

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the Decrypt method with the wrong key:", t, func() {

        aes, err := aes256.New(key)
        So(err,  ShouldBeNil)

        Convey("Encrypt our plain text", func() {

            ciphertextArray, err := aes.Encrypt(plaintext)
            So(err,  ShouldBeNil)

            aes2, err := aes256.New(key + "foo")
            So(err,  ShouldBeNil)

            deciphered_text, err := aes2.Decrypt(ciphertextArray)
            So(err,  ShouldNotBeNil)

            So(deciphered_text,  ShouldBeNil)

        })
    })

}

//eof//