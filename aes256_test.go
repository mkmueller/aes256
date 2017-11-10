package aes256_test

import (
    "mkmueller/aes256"
    "fmt"
    "testing"
    "reflect"
    . "github.com/smartystreets/goconvey/convey"
)


// set the plaintext and key variables for use in the test routines
var plaintext string = "The thing about space is that it's black, and the thing "+
"about a black hole is that it's black.  So how are you supposed to see it?";
var key string       = "12345678901234567890"


func Test_10_Version ( t *testing.T ) {

    var expectedVersion  = "1.0"

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("The version number should be greater than "+ expectedVersion, t, func() {

        So( aes256.Version, ShouldBeGreaterThanOrEqualTo, expectedVersion )

    })

}



func Test_20_New ( t *testing.T ) {

    // define an empty struct for comparizon later
    var empty aes256.Cipher;


    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("New method will accept a key of any size:", t, func() {

        //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
        Convey("\nGiven a key of 80 bytes", func() {
            aes, err := aes256.New("12345678901234567890123456789012345678901234567890123456789012345678901234567890")

            Convey("The error should be nil", func() {
                So(err,  ShouldBeNil)

                Convey("... and returned struct thingie should have a type of 'aes256.Cipher'", func() {
                    theType := fmt.Sprintf("%T", aes)
                    So(theType, ShouldEqual, "aes256.Cipher")

                    Convey("... and, or course, it should not be empty", func() {
                        So( reflect.DeepEqual(aes, empty),  ShouldBeFalse )
                    })

                })

            })

        })



        //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
        Convey("\nGiven a key of 1 byte", func() {
            aes, err := aes256.New("1")

            Convey("The error should be nil", func() {
                So(err,  ShouldBeNil)

                Convey("... and returned struct thingie should have a type of 'aes256.Cipher'", func() {
                    theType := fmt.Sprintf("%T", aes)
                    So(theType, ShouldEqual, "aes256.Cipher")

                    Convey("... and, or course, it should not be empty", func() {
                        So( reflect.DeepEqual(aes, empty),  ShouldBeFalse )
                    })

                })

            })

        })



        //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
        Convey("\nGiven an empty key, we expect an error", func() {
            aes, err := aes256.New("")

            Convey("The error value should not be nil", func() {
                So(err,  ShouldNotBeNil)

                Convey("... and we should have an error message", func() {
                    So( err.Error(),  ShouldNotEqual, "" )

                    Convey("... and the returned object should be empty", func() {
                        So( reflect.DeepEqual(aes, empty),  ShouldBeTrue )
                    })

                })

            })

        })

    })








    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("New method will accept a rehash argument:", t, func() {



        //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
        Convey("\nGiven a rehash value of 1,000,000", func() {
            aes, err := aes256.New("123456789012345678901", 1000000)

            Convey("The error should be nil", func() {
                So(err,  ShouldBeNil)

                Convey("... and returned struct thingie should have a type of 'aes256.Cipher'", func() {
                    theType := fmt.Sprintf("%T", aes)
                    So(theType, ShouldEqual, "aes256.Cipher")

                    Convey("... and, or course, it should not be empty", func() {
                        So( reflect.DeepEqual(aes, empty),  ShouldBeFalse )
                    })

                })

            })

        })



        //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
        Convey("\nNow try a rehash value of 0", func() {
            aes, err := aes256.New("123456789012345678901", 0)

            Convey("The error should be nil", func() {
                So(err,  ShouldBeNil)

                Convey("... and returned struct thingie should have a type of 'aes256.Cipher'", func() {
                    theType := fmt.Sprintf("%T", aes)
                    So(theType, ShouldEqual, "aes256.Cipher")

                    Convey("... and, or course, it should not be empty", func() {
                        So( reflect.DeepEqual(aes, empty),  ShouldBeFalse )
                    })

                })

            })

        })





    })

}









func Test_30_Encrypt ( t *testing.T ) {


    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the Encrypt method:", t, func() {

        //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
        Convey("\nGiven a plaintext variable:", func() {

            aes, err := aes256.New(key)
            ciphertextArray, err := aes.Encrypt(plaintext)

            Convey("The error should be nil", func() {
                So(err,  ShouldBeNil)

                Convey("... and type of the ciphertext should be []uint8", func() {
                    theType := fmt.Sprintf("%T", ciphertextArray)
                    So(theType, ShouldEqual, "[]uint8")

                    Convey("... and the length of the ciphertext should be greater than 32 bytes", func() {
                        So(len(ciphertextArray),  ShouldBeGreaterThan, 32)
                    })

                })

            })

        })

    })



}





func Test_40_Decrypt ( t *testing.T ) {

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the Decrypt method:", t, func() {

        Convey("Start by encrypting the plaintext", func() {

            aes, err := aes256.New(key)
            So(err,  ShouldBeNil)

            ciphertextArray, err := aes.Encrypt(plaintext)
            So(err,  ShouldBeNil)

            Convey("Now decrpyt the ciphertext array", func() {
                deciphered_text, err := aes.Decrypt(ciphertextArray)

                Convey("So the error should be nil", func() {
                    So(err,  ShouldBeNil)

                    Convey("... and the deciphered text should equal the original plain text", func() {
                        So(deciphered_text,  ShouldEqual, plaintext)
                    })

                })

            })

        })

    })

}




func Test_45_DecryptBogus ( t *testing.T ) {

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the Decrypt method on bogus data:", t, func() {
        aes, err := aes256.New(key)
        So(err,  ShouldBeNil)




        Convey("\nTry an empty ciphertext array", func() {
            emptyArray := []byte("")

            Convey("Now attempt to decrpyt the empty array", func() {
                deciphered_text, err := aes.Decrypt(emptyArray)

                Convey("So the error should not be nil", func() {
                    So(err,  ShouldNotBeNil)

                    Convey("... and the deciphered text string should be blank", func() {
                        So(deciphered_text,  ShouldBeBlank)
                    })

                })

            })

        })




        Convey("Create a bogus ciphertext array", func() {
            bogusArray := []byte("this is bogus")

            Convey("Now attempt to decrpyt the bogus array", func() {
                deciphered_text, err := aes.Decrypt(bogusArray)

                Convey("So the error should not be nil", func() {
                    So(err,  ShouldNotBeNil)

                    Convey("... and the deciphered text string should be blank", func() {
                        So(deciphered_text,  ShouldBeBlank)
                    })

                })

            })

        })



        Convey("Create a ciphertext array with one byte changed", func() {

            bogusArray, err := aes.Encrypt(plaintext)
            So(err,  ShouldBeNil)

            foo := make([]byte, 1)
            i := len(bogusArray) -1
            copy(bogusArray[i:i+1], foo[0:1]   )

            Convey("Now attempt to decrpyt the bogus array", func() {
                deciphered_text, err := aes.Decrypt(bogusArray)

                Convey("So the error should not be nil", func() {
                    So(err,  ShouldNotBeNil)
                    println(err.Error())

                    Convey("... and the deciphered text string should be blank", func() {
                        So(deciphered_text,  ShouldBeBlank)
                    })

                })

            })

        })




    })

}




func Test_47_DecryptWithWrongKey ( t *testing.T ) {

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the Decrypt method with the wrong key:", t, func() {

        aes, err := aes256.New(key)
        So(err,  ShouldBeNil)

        Convey("Encrypt our plain text", func() {

            ciphertextArray, err := aes.Encrypt(plaintext)
            So(err,  ShouldBeNil)

            Convey("Now attempt to decrpyt it with the wrong key", func() {

                aes2, err := aes256.New(key + "foo")
                So(err,  ShouldBeNil)

                deciphered_text, err := aes2.Decrypt(ciphertextArray)
                So(err,  ShouldNotBeNil)

                So(deciphered_text,  ShouldBeBlank)

            })
        })
    })





}





func Test_50_EncryptB64 ( t *testing.T ) {

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the EncryptB64 method (encrypt directly to a base-64 string):", t, func() {

        //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
        Convey("\nGiven a plaintext variable:", func() {

            aes, err := aes256.New(key)
            ciphertextB64, err := aes.EncryptB64(plaintext)



            Convey("The error should be nil", func() {
                So(err,  ShouldBeNil)

                Convey("... and type of the ciphertext should be string", func() {
                    theType := fmt.Sprintf("%T", ciphertextB64)
                    So(theType, ShouldEqual, "string")

                    Convey("... and the length of the ciphertext should be greater than 32 bytes", func() {
                        So(len(ciphertextB64),  ShouldBeGreaterThan, 32)
                    })

                })

            })

        })

    })

}



func Test_60_DecryptB64 ( t *testing.T ) {

    //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
    Convey("Test the DecryptB64 method (decrypt from a base-64 string):", t, func() {

        Convey("Start by encrypting the plaintext", func() {

            aes, err := aes256.New(key)
            So(err,  ShouldBeNil)

            ciphertextB64, err := aes.EncryptB64(plaintext)
            So(err,  ShouldBeNil)

            Convey("Now decrpyt the ciphertext", func() {

                deciphered_text, err := aes.DecryptB64(ciphertextB64)

                Convey("So the error should be nil", func() {
                    So(err,  ShouldBeNil)

                    Convey("... and the deciphered text should equal the original plain text", func() {
                        So(deciphered_text,  ShouldEqual, plaintext)
                    })

                })

            })

        })

    })

}



//eof//