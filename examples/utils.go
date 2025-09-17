package examples

import "github.com/consensys/gnark/backend/groth16"

type Test_ProverKeys struct {
	ProvingKey groth16.ProvingKey
}

type Test_VerifierKeys struct {
	VerifyingKey groth16.VerifyingKey
}
