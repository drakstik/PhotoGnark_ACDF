package camera

import (
	"fmt"

	"github.com/drakstik/PhotoGnark_ACDF/image"
	"github.com/drakstik/PhotoGnark_ACDF/photoproof"
)

// Returns a new photograph and proves originality.
func (cam *Camera) TakePhotograph(flag string) (photoproof.Photograph, error) {
	fmt.Println("********[Camera] Taking photograph********")
	img, err := image.NewImage("random") // Get new random image
	if err != nil {
		fmt.Println("Error while running NewImage(): " + err.Error())
	}

	original_signature, err := cam.Admin.Sign(img) // Sign the image as the camera Admin
	if err != nil {
		fmt.Println("[TakePhotograph()] Error while signing a new image")
		return photoproof.Photograph{}, err
	}

	// Construct a new Photograph instant
	photo := photoproof.Photograph{
		Z: image.Z{
			Img:                img,
			Original_PublicKey: cam.Admin.PublicKey,
			Original_Signature: original_signature,
			Original_Hash:      image.ImageHash(img),
		},
		Proof: photoproof.Proof{
			PCD_Proof: nil, // Case 1: This is an original image
			Signature: original_signature,
		},
		ProvingKeys:   cam.ProvingKey,
		VerifyingKeys: cam.VerifyingKey,
	}

	cam.Photographs = append(cam.Photographs, photo) // Add photo to list of photos in camera

	// Construct new identity transformation and parameters
	identity_tr := photoproof.Identity_Tr{Flag: 1}
	params := photoproof.Identity_Tr_Params{}

	// Prove originality of image (Case 1)
	og_proof, err := cam.Admin.Prove(photo, photo, identity_tr, params)
	if err != nil {
		fmt.Println("[TakePhotograph()] Error while proving a new image")
		return photoproof.Photograph{}, err
	}

	// Set photo's PCD proof
	photo.Proof.PCD_Proof = og_proof

	return photo, err
}
