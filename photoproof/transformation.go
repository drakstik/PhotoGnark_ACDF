package photoproof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/drakstik/PhotoGnark_ACDF/image"
)

// Interface for parameters of a transformation
type Transformation_Parameters interface {
	GetName() string
	ToFr() Fr_Transformation_Parameters
}

// Interface for a transformation
type Transformation interface {
	GetName() string
	Apply(img image.Image, params *Transformation_Parameters) image.Image
}

/*--------------------------------------Gnark-Friendly Transformations---------------------------------*/

// [Gnark-friendly] Interface for parameters of a transformation
type Fr_Transformation_Parameters interface {
	GetName() frontend.Variable
}

// [Gnark-friendly] Interface for a transformation
type Fr_Transformation interface {
	GetName() frontend.Variable // Name of the transformation

	// In-circuit application of a transformation
	Apply(api frontend.API, circuit PhotoGnark) frontend.Variable

	// Returns 1 if transformation is allowed to occur
	GetFlag() frontend.Variable
}
