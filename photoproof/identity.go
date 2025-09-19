package photoproof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/drakstik/PhotoGnark_ACDF/image"
)

/*--------------------------------------------Identity Transformation--------------------------------------------*/

// An "identity" transformation returns the same image
type Identity_Tr struct{}

// Extend Transformation interface
func (id_tr Identity_Tr) GetName() string {
	return "identity"
}

// Extend Transformation interface
// Return the given image
func (id_tr Identity_Tr) Apply(img image.Image, params *Transformation_Parameters) image.Image {
	return img
}

/*------------------------------------Gnark-Friendly Identity Transformation-------------------------------------*/

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
func (id_tr Fr_Identity_Tr) Apply(api frontend.API, circuit PhotoGnark) frontend.Variable {
	// TODO

	return 1
}
