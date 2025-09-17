package examples

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/drakstik/PhotoGnark_ACDF/image"
	"github.com/drakstik/PhotoGnark_ACDF/photoproof"
)

/*
	 [Gnark-circuit] Prove & verify knowledge of an image, such that its hash is equal to some public Hash
		 Secret values: Img
		 Public values: ImgHash
	 *When verifying a proof, use dummy values for the secret values, but you need to know the public values.
*/
type Circuit_Example_1 struct {
	Img     image.Fr_Image    `gnark:",secret"`
	ImgHash frontend.Variable `gnark:",public"`
}

// Circuit definition of Circuit_Example_1
//
//		Verifier: Only needs to know the hash of the image, not the image itself.
//		Prover: Must know both the image and the hash.
//	 Circuit: Check that ImgHash == hash(Img_in)
func (circuit Circuit_Example_1) Define(api frontend.API) error {
	in_circuit_hash := image.Fr_ImageHash(api, circuit.Img) // In-circuit hashing
	// Check that circuit.ImgHash is equal to result from in-circuit hashing
	api.AssertIsEqual(in_circuit_hash, circuit.ImgHash)

	return nil
}

func Example_1_Generator(circuit *Circuit_Example_1) (Test_ProverKeys, Test_VerifierKeys, error) {
	// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
	compliance_predicate_id, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("[Generator]: ERROR while compiling constraint system")
		return Test_ProverKeys{}, Test_VerifierKeys{}, err
	}

	// Generate PCD Keys from the compliance_predicate
	provingKey, verifyingKey, err := groth16.Setup(compliance_predicate_id)
	if err != nil {
		fmt.Println("[Generator]: ERROR while generating PCD Keys from the constraint system")
		return Test_ProverKeys{}, Test_VerifierKeys{}, err
	}

	fmt.Println("********Test_Generator was successful!********")
	return Test_ProverKeys{ProvingKey: provingKey},
		Test_VerifierKeys{VerifyingKey: verifyingKey}, err
}

func Example_1_Admin() (Test_ProverKeys, Test_VerifierKeys, error) {
	admin_circuit := Circuit_Example_1{}

	return Example_1_Generator(&admin_circuit)
}

func Example_1_Prover(pr_k Test_ProverKeys) (groth16.Proof, []byte, signature.PublicKey, []byte, error) {
	/* Create a new image and user */
	img, _ := image.NewImage("random")
	prover := photoproof.NewUser()

	/* Sign the image */
	digest := image.ImageHash(img) // Use ToBytes as hash

	hFunc := hash.MIMC_BN254.New()                         // Instantiate MIMC BN254 hash function
	signature, err := prover.SecretKey.Sign(digest, hFunc) // Sign the digest's bytes with the hash function
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
		return nil, nil, nil, nil, err
	}

	// fmt.Println(img.ToFr())

	prover_circuit := Circuit_Example_1{
		Img:     image.ImageToFr(img),
		ImgHash: digest,
	}

	// Create the secret witness from the circuit (runs Define())
	secret_witness_out, err := frontend.NewWitness(&prover_circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
		return nil, nil, nil, nil, err
	}

	// Set the security parameter and compile a constraint system (aka compliance_predicate) (runs Define())
	compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &prover_circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create pcd_proof_out that the secret witness adheres to the compliance predicate, using the given proving key (runs Define())
	pcd_proof_out, err := groth16.Prove(compliance_predicate, pr_k.ProvingKey, secret_witness_out)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	fmt.Println("********Test_Prover was successful!********")

	return pcd_proof_out, digest, prover.PublicKey, signature, err

}

func Example_1_Verifier(proof groth16.Proof, vk Test_VerifierKeys, digest []byte) (bool, error) {
	dummy_image, _ := image.NewImage("random")
	assignment := Circuit_Example_1{
		Img:     image.ImageToFr(dummy_image), // Secret value can be dummy value when verifying
		ImgHash: digest,
	}

	// Recreate a secret witness with public values
	secret_witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("ERROR: frontend.NewWitness() while creating witness...\n" + err.Error())
		return false, err
	}

	// Recreate the public witness from the secret witness
	public_witness, err := secret_witness.Public()
	if err != nil {
		fmt.Println("ERROR: secret_witness.Public() while verifying proof..")
		return false, err
	}

	// Verify the proof with the recreated public witness and verifying key
	err = groth16.Verify(proof, vk.VerifyingKey, public_witness)
	if err != nil {
		fmt.Println("ERROR: VerifyGnarkProof failed.")
		return false, err
	}

	fmt.Println("********Test_Verifier was successful!********")
	return true, err

}

func Example_1_Run() error {
	pr_k, vk, err := Example_1_Admin()
	if err != nil {
		return err
	}

	proof, digest, _, _, err := Example_1_Prover(pr_k)
	if err != nil {
		return err
	}

	ok, err := Example_1_Verifier(proof, vk, digest)
	if err != nil {
		return err
	}

	if !ok {
		fmt.Println("Hashing_Test_Viewer has failed!")
	}

	return nil
}
