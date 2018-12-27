package aesrw

import "fmt"
import "math/rand"
import (
	"testing"
	"os"
	"crypto/aes"

	crypto_rand "crypto/rand"
	"io"
)

//Characters to use in random strings
const CHRB = "!\"#$%&\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f"

//Max string length to test
const MAXL = 999

//Generate a slice of random bytes of length n
//using characters in CHRB
func RandomBytes(n int) []byte {
	s := make([]byte, n)
	l64 := int64(len(CHRB))
	for i := range s {
		s[i] = CHRB[rand.Int63()%l64]
	}
	return s
}

//Generate a slice of random string of length n
//using characters in CHRB
func RandomString(n int) string {
	return string(RandomBytes(n))
}

//Test generating random strings, encrypting them, decrypting them
//and verifying the result is same as the start
func TestString(t *testing.T) {
	var keyLen = []int{16, 24, 32}
	for i := 0; i < 999; i++ {
		k := RandomBytes(keyLen[i%len(keyLen)]) //Random encryption key of length 16, 24 or 32
		s1 := RandomString(rand.Int() % MAXL)   //Random start
		s2, e := EncryptString(s1, k)           //Encrypted
		if e != nil {
			t.Error(fmt.Sprintf("%s", e))
		}
		s3, e := DecryptString(s2, k) //Decrypted
		if e != nil {
			t.Error(fmt.Sprintf("%s", e))
		}
		if s1 != s3 {
			t.Error("Original and decrypted strings do not match!")
		}
	}
}

func TestNewReaderWithIV(t *testing.T) {
	filename := "cipher.text"
	w, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer func() {
		os.Remove(filename)
	}()


	iv := make([]byte, aes.BlockSize)
	key := make([]byte, aes.BlockSize)
	_, err = crypto_rand.Reader.Read(iv)
	if err != nil {
		panic(err)
	}
	_, err = crypto_rand.Reader.Read(key)
	if err != nil {
		panic(err)
	}
	aw, err := NewWriterWithIV(w, key, iv)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 100; i ++ {
		data := []byte("abcdefghijklm\nafaldjfladjflaj12312489123401823904890123408ajsdljflajdlj")
		_, err := aw.Write(data)
		if err != nil {
			panic(err)
		}
	}

	err = aw.Close()
	if err != nil {
		panic(err)
	}

	err = w.Close()
	if err != nil {
		panic(err)
	}

	r, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	ar, err := NewReaderWithIV(r, key, iv)
	if err != nil {
		panic(err)
	}
	data := make([]byte, 100)

	for {
		_, err := ar.Read(data)
		if err == io.EOF {
			fmt.Println("\n=======>done<============")
			break
		}
		fmt.Print(string(data))
	}
}
