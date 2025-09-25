package photoproof

import (
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/drakstik/PhotoGnark_ACDF/image"
)

// Shareable proof
type Proof struct {
	PCD_Proof groth16.Proof
	Signature []byte
}

// Prover keys from the Admin
type ProverKeys struct {
	ProvingKey         groth16.ProvingKey
	Original_PublicKey signature.PublicKey
}

// Verifier keys from the Admin
type VerifierKeys struct {
	VerifyingKey       groth16.VerifyingKey
	Original_PublicKey signature.PublicKey
}

// This is what is shared from node to node.
type Photograph struct {
	Z             image.Z
	Proof         Proof
	ProvingKeys   ProverKeys
	VerifyingKeys VerifierKeys
}
