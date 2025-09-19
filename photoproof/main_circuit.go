package photoproof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/PhotoGnark_ACDF/image"
)

type PhotoGnark struct {
	Img_in        image.Fr_Z        `gnark:",secret"`
	Img_out       image.Fr_Z        `gnark:",public"`
	Signature_out eddsa.Signature   `gnark:",secret"`
	Originality   frontend.Variable `gnark:",secret"`
}

func (circuit PhotoGnark) Define(api frontend.API) error {

	ok := api.Select(
		circuit.Originality,
		Verify_Original_Signature(api, circuit),
		Check_Transformation(api, circuit),
	)

	// Assert that VerifySignature or CheckTransformation return 1
	api.AssertIsEqual(ok, 1)

	return nil
}

func Check_Transformation(api frontend.API, circuit PhotoGnark) frontend.Variable {

	/* Input public key and output public key must be the same. */
	api.AssertIsEqual(circuit.Img_in.PublicKey.A.X, circuit.Img_out.PublicKey.A.X)
	api.AssertIsEqual(circuit.Img_in.PublicKey.A.Y, circuit.Img_out.PublicKey.A.Y)

	// Section V-F: the original hash is passed from input to output without modification
	api.AssertIsEqual(circuit.Img_in.OriginalHash, circuit.Img_out.OriginalHash)

	// Verify the output signature is valid.
	digest := image.Fr_ImageHash(api, circuit.Img_out.Img)
	Verify_Signature(api, digest, circuit.Signature_out, circuit.Img_out.PublicKey)

	// TODO: ensure that all permissible transformations are applied

	/* Identity Transformation checks that the images are equal to the signature. */
	// api.Select(
	// 	circuit.Identity.Flag,
	// 	circuit.Identity.Apply(api, permissible.Input, permissible.Output, permissible.Parameters, permissible.Signature),
	// 	frontend.Variable(0),
	// )

	return 1
}
