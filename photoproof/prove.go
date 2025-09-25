package photoproof

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
)

//	to test
//
// Case 1: Original image
// Case 2: Potentially edited image
func (user User) Prove(photo_in Photograph, photo_out Photograph, tr Transformation, params Parameters) (groth16.Proof, error) {

	// Assign the output signature to its eddsa equivilant
	var eddsa_sig_out eddsa.Signature
	eddsa_sig_out.Assign(1, photo_out.Proof.Signature)

	/* Case 1: Function was called by camera */
	if photo_in.Proof.PCD_Proof == nil {

		og_proof, err := ProveOriginal(photo_in, eddsa_sig_out) // Initial pcd_proof
		if err != nil {
			fmt.Println("Error in ProveOriginal(), Prove()\n" + err.Error())
			return nil, err
		}
		fmt.Println("********Proving Originality was successful...********")
		return og_proof, err
	}

	var eddsa_pk_out eddsa.PublicKey
	eddsa_pk_out.Assign(1, user.PublicKey.Bytes())

	/* Case 2: Else create a proof for the transformation */
	circuit := PhotoGnark{}

	switch tr.GetName() {
	case "identity":
		circuit = PhotoGnark{
			Z_in:          photo_in.Z.ToFr(),
			Z_out:         photo_out.Z.ToFr(),
			PublicKey_out: eddsa_pk_out,
			Signature_out: eddsa_sig_out,
			Originality:   0, // Case 2: NOT original image

			Parameters: params.ParamsToFr(),
			Identity: Fr_Identity_Tr{
				Flag: 1,
			},
		}
	default:
		fmt.Println("Transformation name is unknown")
	}

	// Create the secret witness from the circuit
	secret_witness_out, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	// Set the security parameter and compile a constraint system (aka compliance_predicate)
	compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, err
	}

	// Create proof_out that the secret witness adheres to the compliance predicate, using the given proving key
	proof_out, err := groth16.Prove(compliance_predicate, photo_in.ProvingKeys.ProvingKey, secret_witness_out)
	if err != nil {
		return nil, err
	}

	return proof_out, nil
}

// Case 1: This is an original photo.
func ProveOriginal(photo_in Photograph, signature eddsa.Signature) (groth16.Proof, error) {
	// Construct a compliance predicate with Originality being set to true (or 1).
	circuit := PhotoGnark{
		Z_in:          photo_in.Z.ToFr(),
		Z_out:         photo_in.Z.ToFr(),
		PublicKey_out: photo_in.Z.ToFr().Original_PublicKey,
		Signature_out: signature,
		Originality:   1, // Original image
		Parameters:    Fr_Identity_Tr_Params{},
		Identity:      Fr_Identity_Tr{Flag: 1},
	}

	// Create the secret witness from the circuit (runs Define())
	secret_witness_out, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	// Set the security parameter and compile a constraint system (aka compliance_predicate) (runs Define())
	compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, err
	}

	// Create pcd_proof_original that the secret witness adheres to the compliance predicate, using the given proving key (runs Define())
	pcd_proof_original, err := groth16.Prove(compliance_predicate, photo_in.ProvingKeys.ProvingKey, secret_witness_out)
	if err != nil {
		return nil, err
	}

	return pcd_proof_original, err
}
