package photoproof

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

func Verify_Signature(api frontend.API, digest frontend.Variable, dig_sig eddsa.Signature, public_key eddsa.PublicKey) frontend.Variable {

	h, _ := mimc.NewMiMC(api)

	// Set the twisted edwards curve to use
	curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)

	// verify the digest against the signature, using the public key
	eddsa.Verify(curve, dig_sig, digest, public_key, &h)

	return 1
}
