package image

/* Constants */
const N uint64 = 5
const N2 uint64 = N * N // Total number of pixels in an image is N*N
const P uint64 = 10

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

// Object representing an Image's transformation bound credit.
//
// As described in Section V-G, "Image provenance tracking":
//
//	To mitigate the risk of numerous small permissible transformations accumulating
//	into an overall change that is considered impermissible,
//	we can use a "provenance" metadata field in the image (the field should be hashed alongside pixels)
//	to bound transformations based on how many times they occurs or the size of the image.
type Provenance struct {
	// Transformation name for which this Provenance rule refers to
	Tr_Name uint64
	// Count or degrees or percentage of image size that is allowed to be transformed.
	// Originally set by the Secure Camera.
	Tr_Bound uint64
}

/* An image object. */
type Image struct {
	Pxls [N2]Pixel // Single dimension array of size N*N

	PxlBytes []byte // Set by ImageToBytes()

	// This field is a metadata field that sets upper bounds to transformations,
	// 	For example: To maintain total contrast increase bounded at 10% of RGB values, the transformation's
	//				  Apply() function can assert that bound is != 0 and bound is !> 10%, or we can check
	//				  that the provenance's bound is exactly the value we expect it to be after the
	// 				  given transformation occured.
	// This means the verifier will be able to see how much of the allocated provenance bounds has been used up
	// so far. This does not reveal the previous pixel values, the params of the transformation, nor the order of
	// the transformation. Provenance, alongside Pxls, is used to generate PxlBytes.
	Provenance [P]Provenance
}

/*----------------------------------------------- Area Construction -------------------------------------*/
// Represents an area inside an image.
type Area struct {
	Loc    PixelLocation
	Width  uint64 // Starting at 1
	Height uint64 // Starting at 1
}
