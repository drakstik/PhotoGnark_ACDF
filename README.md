# PhotoGnark

This is a project proposed to me by Assistant Professor Wenting Zheng as a final project for her class at CMU, called [15-799: Security for Software and Hardware Systems](https://www.cs.cmu.edu/~15799/schedule.html).

This project uses Gnark (a Golang package for zk-SNARKs) to implement a PhotoProof scheme as described in the paper called ["PhotoProof: Cryptographic Image Authentication for Any Set of Permissible Transformations"](https://ieeexplore.ieee.org/document/7546506/) [1].

## Out-of-Circuit vs. In-circuit

In this project, normal Golang computations are called "out-of-circuit" and can be mirrored into an "in-cricuit" computation.

Similarly a normal Golang object can be mirrored into a Gnark-friendly object, which can be manipulated by computations and assertions that occur within a [Gnark circuit](https://docs.gnark.consensys.io/Concepts/circuits).

### Image vs. Fr_Image

In this project, we represent an image as an array of pixels of size N*N.

```

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

```

We then define a Gnark-friendly mirror version of an Image object that can be manipulated by Gnark circuits. 

We this Gnark-friendly object an *Fr_Image*, where the 'Fr' suffix denotes that the object is useable by Gnark's frontend API.

Gnark-friendly object typically have *frontend.Variable* and other Gnark-friendly objects as fields.

```

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

// [Gnark-friendly] A pixel object
type Fr_Pixel struct {
	RGB [3]frontend.Variable `gnark:",inherit"` // Array representation
	Loc Fr_PixelLocation     `gnark:",inherit"`
}

// [Gnark-friendly] An image object
type Fr_Image struct {
	Pxls     [N2]Fr_Pixel      `gnark:",inherit"`
	PxlBytes frontend.Variable `gnark:",inherit"`
}

```

We then define function `ImageToFr(img Image) Fr_Image` which returns an *Fr_Image* mirror representation of the input *Image*.

### ImageHash() vs. Fr_ImageHash()

Now we can create Gnark circuits with fields of type *Fr_Image*.

Next, we must define in-circuit and out-of-circuit hashing functions for both a normal *Image* and an *Fr_Image*. 

When we run `NewImage()`, we receive a new image with its PxlBytes field set from the functions `ImageToBigInt()` and `BigInt_to_Fr_Bytes()`. 

An *Image*'s PxlBytes field is easily represented in a Gnark-friendly way as a *frontend.Variable*, such that both `ImageHash()` and `Fr_ImageHash()` return equivalent hash values.

```
package image

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	out_mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

/* ------------------------------------In-Circuit & Out-of-Circuit Hash Functions-------------------------------- */

// Return MiMC hash digest of the PxlBytes of an Image
func ImageHash(img Image) []byte {
	h := out_mimc.NewMiMC()
	h.Write(img.PxlBytes)
	return h.Sum(nil)
}

// Return MiMC hash digest of the PxlBytes of an Fr_Image
func Fr_ImageHash(api frontend.API, img Fr_Image) frontend.Variable {
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(img.PxlBytes)
	digest := mimc.Sum()
	return digest
}

```


For hashing functions to be equivalent on both sides, an Image's PxlBytes and an Fr_Image's PxlBytes must be equivalent. 

**NOTE:** This project defines *PxlBytes* as value of z as a big-endian byte slice, where z is a field element set to an Image as a *big.Int*. This allows both *Image* and *Fr_Image*'s *PxlBytes* to hash to the same values, such that *a)* signature generation can occur out-of-circuit, and *b)* hash calculation and signature verification can occur in-circuit. See `BigInt_to_Fr_Bytes()` and `ImageToBigInt()` for further understanding of how we do this.

### Circuit Definition

[TODO]


## Bibliography

[1] A. Naveh and E. Tromer, "PhotoProof: Cryptographic Image Authentication for Any Set of Permissible Transformations," 2016 IEEE Symposium on Security and Privacy (SP), San Jose, CA, USA, 2016, pp. 255-271, doi: 10.1109/SP.2016.23.
