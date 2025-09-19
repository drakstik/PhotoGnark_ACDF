package camera

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/drakstik/PhotoGnark_ACDF/photoproof"
)

func NewCamera() Camera {
	prover, verifier, admin := Generator(&photoproof.PhotoGnark{})
	return Camera{
		Admin:       admin,
		Photographs: []Photograph{},
		Prover:      prover,
		Verifier:    verifier,
	}
}

func Generator(circuit *photoproof.PhotoGnark) (ProverKeys, VerifierKeys, photoproof.User) {
	// Create a new user, including their secret key.
	user := photoproof.NewUser()

	// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
	compliance_predicate_id, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("[Generator]: ERROR while compiling constraint system")
		return ProverKeys{}, VerifierKeys{}, photoproof.User{}
	}

	// Generate PCD Keys from the compliance_predicate
	provingKey, verifyingKey, err := groth16.Setup(compliance_predicate_id)
	if err != nil {
		fmt.Println("[Generator]: ERROR while generating PCD Keys from the constraint system")
		return ProverKeys{}, VerifierKeys{}, photoproof.User{}
	}

	fmt.Println("********PhotoGnark Generator was successful!********")

	return ProverKeys{ProvingKey: provingKey, Original_PublicKey: user.PublicKey},
		VerifierKeys{VerifyingKey: verifyingKey, Original_PublicKey: user.PublicKey},
		user
}
