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

	// TODO: This Provenance field must be mirrored into an Fr_Image
	//			- It is mainly used to maintain provenance length by setting an upper bound to transformations
	//				For example: Cropping can be bound to 25% of the image, so for each cropping the % allowed
	//							 should be reduced acordingly, and check that provenance bound is != 0.
	//			- If provenance bounds are stored in Provenance, then we expose the amount of transformation that
	//				has occured so far. But this is OK because the params of the transformation are not known
	//				as well as previous pixel values, nor the order of transformations. Just the amount of the
	//				transformation bounds credit utilized is revealed.
	//			- Provenance should also be added to the PxlBytes for hashing & signing
	Provenance [P]Provenance
}

/*----------------------------------------------- Area Construction -------------------------------------*/
// Represents an area inside an image.
type Area struct {
	Loc    PixelLocation
	Width  uint64 // Starting at 1
	Height uint64 // Starting at 1
}
