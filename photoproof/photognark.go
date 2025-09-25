package photoproof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/PhotoGnark_ACDF/image"
)

type PhotoGnark struct {
	Z_in          image.Fr_Z        `gnark:",secret"`
	Z_out         image.Fr_Z        `gnark:",public"`
	PublicKey_out eddsa.PublicKey   `gnark:",public"`
	Signature_out eddsa.Signature   `gnark:",secret"`
	Originality   frontend.Variable `gnark:",secret"`

	// TODO add all transformation fields and define them & their params
	// You may add all existing transformation,
	// but their bounds will be controlled by the image's Provenance bounds.
	// For example, blocking cropping can be done with a bound of 0% of the image size .
	Parameters Fr_Parameters `gnark:",secret"`

	/*List of permissible transformations*/
	Identity Fr_Identity_Tr `gnark:",secret"`
}

func (circuit *PhotoGnark) Define(api frontend.API) error {

	ok := api.Select(
		circuit.Originality,                     // 1 if this is an original image
		Verify_Original_Signature(api, circuit), // Case 1
		Check_Transformation(api, circuit),      // Case 2
	)

	// Assert that VerifySignature or CheckTransformation returns 1
	api.AssertIsEqual(ok, 1)

	return nil
}

/*-------------------------------------------Functions used in Define()------------------------------------------*/

// Case 1: Z_in is an original image. Verify Z_in's original hash, signature and public key.
// Only requires Z_in, no need for Z_out.
func Verify_Original_Signature(api frontend.API, circuit *PhotoGnark) frontend.Variable {

	// Section V-F: the original hash matches the image
	digest := image.Fr_ImageHash(api, circuit.Z_in.Img) // Calculate hash in secret
	api.AssertIsEqual(circuit.Z_in.Original_Hash, digest)

	// verify the original hash against the original signature, using the Admin's public key
	Verify_Signature(api, circuit.Z_in.Original_Hash, circuit.Z_in.Original_Signature, circuit.Z_in.Original_PublicKey)

	return 1
}

func Check_Transformation(api frontend.API, circuit *PhotoGnark) frontend.Variable {

	/*
		PhotoProof paper, Pg. 262,
		The goal of including the public key in the message is for
		allowing the final verifier, which knows the public key that
		appears in the system’s verifying key (the Admin's public key),
		to be convinced that the same public key was used for the signature
		verification of the original image.
	*/

	// Requirement: Original Public Key must be shared with all participants
	// 				and asserted to be passed down from Z_in (secret) to Z_out (public).
	api.AssertIsEqual(circuit.Z_in.Original_PublicKey.A.X, circuit.Z_out.Original_PublicKey.A.X)
	api.AssertIsEqual(circuit.Z_in.Original_PublicKey.A.Y, circuit.Z_out.Original_PublicKey.A.Y)

	/*
		PhotoProof paper, Section V-F,
		the original hash is passed from input to output without modification
	*/

	// Requirement: Assert Z_in (secret) and Z_out (public) have equal Original hash
	api.AssertIsEqual(circuit.Z_in.Original_Hash, circuit.Z_out.Original_Hash)

	// Verify the output signature is valid. This is useful for the verifier to recognize that
	// the prover's Z_out image is the same as the known Z_out, and signature can be kept secret.
	digest := image.Fr_ImageHash(api, circuit.Z_out.Img)
	Verify_Signature(api, digest, circuit.Signature_out, circuit.PublicKey_out)

	// TODO: ensure that the  permissible transformations are applied

	/* Identity Transformation checks that the images are equal to the signature. */
	result := api.Select(
		circuit.Identity.Flag,
		circuit.Identity.Apply(api, circuit),
		frontend.Variable(0),
	)

	// Example of how to apply a new transformation
	/*
		result = api.Select(
					result, // If other transformation has already occured, do not apply any other transformation
					1,
					api.Select(
						circuit.tr.Flag,
						circuit.tr.Apply(api, circuit),
						0),
					)
	*/

	/*
		This ensures that at least one transformation is required to create a proof,
		including proof of originality.

		result == 1, then at least one transformation's flag is 1 and applying tr is successful
		result == 0, no transformation was applied

		*NOTE: tr.Apply must always return 1 and assert some relationship between Z_in and Z_out.
	*/
	api.AssertIsEqual(1, result)

	return 1
}
