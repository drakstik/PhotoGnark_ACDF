package image

import (
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
)

/*-------------------------------------------- Z Construction -------------------------------------------*/
// Z = (Image, Public Key, original hash & signature)
type Z struct {
	Img                Image
	Original_PublicKey signature.PublicKey
	// Original signature and hash
	Original_Signature []byte
	Original_Hash      []byte
}

func (z Z) ToFr() Fr_Z {
	// Assign the PK & SK to their eddsa equivilant
	var eddsa_digSig eddsa.Signature
	var eddsa_PK eddsa.PublicKey

	eddsa_digSig.Assign(1, z.Original_Signature)
	eddsa_PK.Assign(1, z.Original_PublicKey.Bytes())

	return Fr_Z{
		Img:                ImageToFr(z.Img),
		Original_PublicKey: eddsa_PK,
		Original_Signature: eddsa_digSig,
		Original_Hash:      frontend.Variable(z.Original_Hash),
	}
}

/*------------------------------------------ Gnark-Friendly Z --------------------------------------*/
type Fr_Z struct {
	Img                Fr_Image
	Original_PublicKey eddsa.PublicKey
	// Original signature and hash
	Original_Signature eddsa.Signature
	Original_Hash      frontend.Variable
}
