package photoproof

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/PhotoGnark_ACDF/image"
)

func Verify_Original_Signature(api frontend.API, circuit PhotoGnark) frontend.Variable {

	// Section V-F: the original hash matches the image
	digest := image.Fr_ImageHash(api, circuit.Img_in.Img)
	api.AssertIsEqual(circuit.Img_in.OriginalHash, digest)

	// verify the original hash against the original signature, using the Admin's public key
	Verify_Signature(api, circuit.Img_in.OriginalHash, circuit.Img_in.OriginalSignature, circuit.Img_in.PublicKey)

	return 1
}

func Verify_Signature(api frontend.API, digest frontend.Variable, dig_sig eddsa.Signature, public_key eddsa.PublicKey) frontend.Variable {

	h, _ := mimc.NewMiMC(api)

	// Set the twisted edwards curve to use
	curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)

	// verify the digest against the signature, using the public key
	eddsa.Verify(curve, dig_sig, digest, public_key, &h)

	return 1
}
