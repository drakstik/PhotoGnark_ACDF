package photoproof

import (
	"fmt"

	"github.com/drakstik/PhotoGnark_ACDF/image"
)

// Input: Photograph, transformation, parameters
// Output: Photograph with proof that the transformation occured in compliance with Admin's circuit
func (user User) Edit(photo_in Photograph, tr Transformation, params Parameters) (Photograph, error) {
	fmt.Println("********Editor********")
	img_out := tr.Apply(photo_in.Z.Img, &params) // Apply the transformation to the image

	signature_out, err := user.Sign(img_out)
	if err != nil {
		fmt.Println("[Edit] Signing image failed")
		return Photograph{}, err
	}

	photo_out := Photograph{
		Z: image.Z{
			Img:                img_out,
			Original_PublicKey: photo_in.ProvingKeys.Original_PublicKey,
			Original_Signature: photo_in.Z.Original_Signature,
			Original_Hash:      photo_in.Z.Original_Hash,
		},
		Proof: Proof{
			PCD_Proof: nil, // photo_out must now get proven compliant
			Signature: signature_out,
		},
		ProvingKeys:   photo_in.ProvingKeys,
		VerifyingKeys: photo_in.VerifyingKeys,
	}

	// Prove photo_out is compliant with Admin's circuit
	proof_out, err := user.Prove(photo_in, photo_out, tr, params)
	if err != nil {
		fmt.Println("[Edit] Proving image failed\n" + err.Error())
		return Photograph{}, err
	}

	// Set the PCD proof, claiming compliance to the
	photo_out.Proof.PCD_Proof = proof_out

	return photo_out, err
}
