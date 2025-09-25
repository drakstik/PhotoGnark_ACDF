package photoproof

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/drakstik/PhotoGnark_ACDF/image"
)

type User struct {
	SecretKey signature.Signer
	PublicKey signature.PublicKey
}

func NewUser() User {
	// 1. Generate a secret & public key using ceddsa.
	secret_key, err := ceddsa.New(1, rand.Reader) // Generate a secret key for signing
	if err != nil {
		fmt.Println("func NewSecretKey(): Error while generating secret key using ceddsa...")
		fmt.Print(err.Error())
		return User{}
	}

	return User{
		SecretKey: secret_key,
		PublicKey: secret_key.Public(),
	}

}

// Out-of-circuit signing function,
// Hashes the image using ImageHash and signs it with the user's secret key.
func (user User) Sign(img image.Image) ([]byte, error) {
	// Hash the img
	digest := image.ImageHash(img)

	// Instantiate MIMC BN254 hash function, to be used in signing the image
	hFunc := hash.MIMC_BN254.New()

	// Sign the digest with the hash function
	signature, err := user.SecretKey.Sign(digest, hFunc)
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
		return nil, err
	}

	return signature, err
}
