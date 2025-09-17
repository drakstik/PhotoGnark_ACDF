package image

import "github.com/consensys/gnark/frontend"

// (X,Y) location of pixle -> index location in a single array of pixels
func To_1D_Index(x uint64, y uint64) uint64 {
	return y*N + x
}

// Returns Fr_Pixel, gnark-friendly version of the pixel
func PixelToFr(pxl Pixel) Fr_Pixel {
	return Fr_Pixel{
		RGB: [3]frontend.Variable{pxl.RGB[0], pxl.RGB[1], pxl.RGB[2]},
		Loc: Fr_PixelLocation{X: pxl.Loc.X, Y: pxl.Loc.Y},
	}
}

// Return Fr_Image representation of an Image
func ImageToFr(img Image) Fr_Image {
	// Create new Fr_Image
	fr_image := Fr_Image{
		Pxls: [N2]Fr_Pixel{},
	}

	// For each index i, set fr_image[i] to a Fr version of the pixel in img[i]
	for i := 0; i < int(N2); i++ {
		fr_image.Pxls[i] = PixelToFr(img.Pxls[i])
	}

	// Set PxlBytes
	fr_image.PxlBytes = img.PxlBytes

	return fr_image
}
