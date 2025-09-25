package image

import (
	"github.com/consensys/gnark/frontend"
)

// [Gnark-friendly] location of a pixel
type Fr_PixelLocation struct {
	X frontend.Variable `gnark:",inherit"` // X dimenstion of a 2D matrix
	Y frontend.Variable `gnark:",inherit"` // Y dimension of a 2D matrix
}

// [Gnark-friendly] (X,Y) location of pixle -> frontend.Variable index location in a single array of pixels
func (loc Fr_PixelLocation) To_1D_Index(api frontend.API) frontend.Variable {
	return api.Add(api.Mul(loc.Y, frontend.Variable(N)), loc.X)
}

// [Gnark-friendly] A pixel object that can be manipulated by Gnark circuits
type Fr_Pixel struct {
	RGB [3]frontend.Variable `gnark:",inherit"` // Array representation
	Loc Fr_PixelLocation     `gnark:",inherit"`
}

// [Gnark-friendly] Object representing an Fr_Image's transformation bound credits.
type Fr_Provenance struct {
	Tr_Name  frontend.Variable
	Tr_Bound frontend.Variable
}

// [Gnark-friendly] An image object that can be manipulated by Gnark circuits
type Fr_Image struct {
	Pxls       [N2]Fr_Pixel      `gnark:",inherit"`
	PxlBytes   frontend.Variable `gnark:",inherit"`
	Provenance [P]Fr_Provenance  `gnark:",inherit"`
}

/*------------------------------------------ Gnark-Friendly Area --------------------------------------*/
// Represents an area inside an Fr_Image.
type Fr_Area struct {
	Loc    Fr_PixelLocation
	Width  frontend.Variable // Starting at 1
	Height frontend.Variable // Starting at 1
}
