package examples

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/PhotoGnark_ACDF/image"
	"github.com/drakstik/PhotoGnark_ACDF/photoproof"
)

/*
	 [Gnark-circuit] Prove & verify Prover's knowledge of an image that passes signature verification
		 Secret values: Img_in, Signature, PublicKey
		 Public values: ImgHash
	 *When verifying a proof, use dummy values for the secret values, but you need to know the public values.
*/
type Circuit_Example_2 struct {
	Img_in    image.Fr_Image    `gnark:",secret"`
	Signature eddsa.Signature   `gnark:",secret"`
	PublicKey eddsa.PublicKey   `gnark:",secret"`
	ImgHash   frontend.Variable `gnark:",public"`
}

// Circuit definition of Circuit_Example_2
//
//	Verifier: Only needs to know the hash of the image, not the image itself.
//	Prover: Must know the image, the hash, the public key and signature.
//	Circuit: Verify signature against hash(Img_in) and ImgHash, Check that ImgHash == hash(Img_in)
func (circuit Circuit_Example_2) Define(api frontend.API) error {

	h, _ := mimc.NewMiMC(api)                                  // Instantiate MiMC hash function
	curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254) // Set the twisted edwards curve to use
	// Verify signature against inCircuitHash
	eddsa.Verify(curve, circuit.Signature, circuit.ImgHash, circuit.PublicKey, &h)

	// Verify signature against circuit.ImgHash

	in_circuit_hash := image.Fr_ImageHash(api, circuit.Img_in) // Hash the secret image

	/* This works because the Fr_Image.Hash() is logically similar to frontend.Variable(Image.Hash())*/
	api.AssertIsEqual(in_circuit_hash, in_circuit_hash) // Check that hashes equal each other
	h2, _ := mimc.NewMiMC(api)                          // Need a new MiMC instance
	eddsa.Verify(curve, circuit.Signature, in_circuit_hash, circuit.PublicKey, &h2)

	return nil
}

func Example_2_Generator(circuit *Circuit_Example_2) (Test_ProverKeys, Test_VerifierKeys, error) {
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

func Example_2_Admin() (Test_ProverKeys, Test_VerifierKeys, error) {
	admin_circuit := Circuit_Example_2{}

	return Example_2_Generator(&admin_circuit)
}

func Example_2_Prover(pr_k Test_ProverKeys) (groth16.Proof, signature.PublicKey, []byte, []byte, error) {
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

	// Assign signature to its EdDSA equivalent.
	var eddsa_sig eddsa.Signature
	eddsa_sig.Assign(tedwards.BN254, signature)

	// Assign public key to its EdDSA equivalent.
	var eddsa_PK eddsa.PublicKey
	eddsa_PK.Assign(tedwards.BN254, prover.PublicKey.Bytes())

	circuit := Circuit_Example_2{
		Img_in:    image.ImageToFr(img),
		Signature: eddsa_sig,
		PublicKey: eddsa_PK,
		ImgHash:   digest,
	}

	// Create the secret witness from the circuit (runs Define())
	secret_witness_out, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
		return nil, nil, nil, nil, err
	}

	// Set the security parameter and compile a constraint system (aka compliance_predicate) (runs Define())
	compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create pcd_proof_out that the secret witness adheres to the compliance predicate, using the given proving key (runs Define())
	pcd_proof_out, err := groth16.Prove(compliance_predicate, pr_k.ProvingKey, secret_witness_out)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	fmt.Println("********Test_Prover was successful!********")

	return pcd_proof_out, prover.PublicKey, signature, digest, err

}

func Example_2_Verifier(proof groth16.Proof, pk signature.PublicKey, vk Test_VerifierKeys, digest []byte) (bool, error) {
	dummy_image, _ := image.NewImage("random")
	viewer := photoproof.NewUser()

	/* Sign the image */
	dummy_digest := image.ImageHash(dummy_image) // Use ToBytes as hash

	hFunc := hash.MIMC_BN254.New()                               // Instantiate MIMC BN254 hash function
	signature, err := viewer.SecretKey.Sign(dummy_digest, hFunc) // Sign the digest's bytes with the hash function
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
		return false, err
	}

	// Assign signature to its EdDSA equivalent.
	var dummy_eddsa_sig eddsa.Signature
	dummy_eddsa_sig.Assign(tedwards.BN254, signature)

	// Assign public key to its EdDSA equivalent.
	var eddsa_PK eddsa.PublicKey
	eddsa_PK.Assign(tedwards.BN254, pk.Bytes())

	assignment := Circuit_Example_2{
		Img_in:    image.ImageToFr(dummy_image), // Secret value can be dummy value when verifying
		Signature: dummy_eddsa_sig,
		PublicKey: eddsa_PK,
		ImgHash:   digest,
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
		fmt.Println("ERROR: groth16.Verify failed.")
		return false, err
	}

	fmt.Println("********Test_Verifier was successful!********")
	return true, err

}

func Example_2_Run() error {
	pr_k, vk, err := Example_2_Admin()
	if err != nil {
		return err
	}

	proof, pk, _, digest, err := Example_2_Prover(pr_k)
	if err != nil {
		return err
	}

	ok, err := Example_2_Verifier(proof, pk, vk, digest)
	if err != nil {
		return err
	}

	if !ok {
		fmt.Println("Example_2_Verifier has failed!")
	}

	return nil
}
