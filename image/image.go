package image

/* Constants */
const N uint64 = 5
const N2 uint64 = N * N // Total number of pixels in an image is N*N

/* A pixel object */
type Pixel struct {
	RGB [3]uint8      // Array representation
	Loc PixelLocation // Pixel's 2D location
}

/* The (x,y) location of a pixel */
type PixelLocation struct {
	X uint64 // X dimenstion of a 2D matrix
	Y uint64 // Y dimension of a 2D matrix
}

/* An image object. */
type Image struct {
	Pxls     [N2]Pixel // Single dimension array of size N*N
	PxlBytes []byte    // Set by ImageToBytes()
}
