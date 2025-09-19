package camera

import (
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/drakstik/PhotoGnark_ACDF/image"
	"github.com/drakstik/PhotoGnark_ACDF/photoproof"
)

// Proof that is used outside the circuit
type Proof struct {
	PCD_Proof groth16.Proof
	Signature []byte
}

type ProverKeys struct {
	ProvingKey         groth16.ProvingKey
	Original_PublicKey signature.PublicKey
}

type VerifierKeys struct {
	VerifyingKey       groth16.VerifyingKey
	Original_PublicKey signature.PublicKey
}

type Photograph struct {
	Z            image.Z
	Proof        Proof
	ProverKeys   ProverKeys
	VerifierKeys VerifierKeys
}

type Camera struct {
	Admin       photoproof.User
	Photographs []Photograph
	Prover      ProverKeys
	Verifier    VerifierKeys
}

func (cam *Camera) TakePhotograph(flag string) (image.Image, error) {
	img, err := image.NewImage("random")
	if err != nil {
		fmt.Println("[TakePhotograph()] Error while creating a NewImage()")
		return image.Image{}, err
	}

	return img, err
}
