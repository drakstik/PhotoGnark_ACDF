package image

import (
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
)

/*-------------------------------------------- Z Construction -------------------------------------------*/
// Z = (Image, Public Key)
type Z struct {
	Img       Image
	PublicKey signature.PublicKey
	// Original signature and hash
	OriginalSignature []byte
	OriginalHash      []byte
}

func (z Z) ToFr() Fr_Z {
	// Assign the PK & SK to their eddsa equivilant
	var eddsa_digSig eddsa.Signature
	var eddsa_PK eddsa.PublicKey

	eddsa_digSig.Assign(1, z.OriginalSignature)
	eddsa_PK.Assign(1, z.PublicKey.Bytes())

	return Fr_Z{
		Img:               ImageToFr(z.Img),
		PublicKey:         eddsa_PK,
		OriginalSignature: eddsa_digSig,
		OriginalHash:      frontend.Variable(z.OriginalHash),
	}
}
