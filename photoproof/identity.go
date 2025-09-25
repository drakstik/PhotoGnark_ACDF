package photoproof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/drakstik/PhotoGnark_ACDF/image"
)

/*--------------------------------------------Identity Transformation--------------------------------------------*/

type Identity_Tr_Params struct {
}

func (params Identity_Tr_Params) GetName() string {
	return "identity"
}

func (params Identity_Tr_Params) ParamsToFr() Fr_Parameters {
	return Fr_Identity_Tr_Params{}
}

// An "identity" transformation returns the same image
type Identity_Tr struct {
	Flag int8
}

// Extend Transformation interface
func (id_tr Identity_Tr) GetName() string {
	return "identity"
}

// Extend Transformation interface
// Return the given image
func (id_tr Identity_Tr) Apply(img image.Image, params *Parameters) image.Image {
	return img
}

func (id_tr Identity_Tr) ToFr() Fr_Transformation {
	return &Fr_Identity_Tr{
		Flag: id_tr.Flag,
	}
}

/*------------------------------------Gnark-Friendly Identity Transformation-------------------------------------*/

type Fr_Identity_Tr_Params struct {
}

// "identity" == 0
func (params Fr_Identity_Tr_Params) GetParamsId(api frontend.API) frontend.Variable {
	return 0
}

// [Gnark-friendly] An "identity" transformation checks if input & output images are equal
type Fr_Identity_Tr struct {
	Flag frontend.Variable
}

// Get the transformation's name as a frontend.Variable
func (params Fr_Identity_Tr) GetName() frontend.Variable {
	return frontend.Variable([]byte("identity"))
}

// Return 1 if this transformation is permissible
func (tr Fr_Identity_Tr) GetFlag() frontend.Variable {
	return tr.Flag
}

// Check that img_in & img_out are equivelant.
// return 0 if unsuccessful, 1 if successful
func (id_tr Fr_Identity_Tr) Apply(api frontend.API, circuit *PhotoGnark) frontend.Variable {
	/* PhotoProof paper, Section V-E:

	"Identity transformation checks whether the input and output image are identical.
	Identical images have the same pixel data as well as the same metadata."

	Since Pxlbytes includes the relevant metadata, we can keep the same hashing algorithms
	for a quick equality assertion.
	*/

	// First, check if identity provenance bound is correct
	api.AssertIsEqual(1, circuit.Z_in.Img.Provenance[0].Tr_Bound)

	imgHash_in := image.Fr_ImageHash(api, circuit.Z_in.Img)
	imgHash_out := image.Fr_ImageHash(api, circuit.Z_out.Img)

	// Assert that hashes are equal
	api.AssertIsEqual(imgHash_in, imgHash_out)

	return 1
}
