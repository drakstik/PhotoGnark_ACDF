package image

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	out_mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

/* ----------------------------------------Hashing Utility Functions---------------------------------------- */

// Returns big.Int representation of an Image
// Pack each pixel RGB values into a single big.Int
func ImageToBigInt(img Image) *big.Int {
	packed := make([]uint32, len(img.Pxls))
	for i, px := range img.Pxls {
		packed[i] = uint32(px.RGB[0])<<16 | uint32(px.RGB[1])<<8 | uint32(px.RGB[2])
	}

	result := big.NewInt(0)
	for _, v := range packed {
		// Shift the current value by 32 bits to the left
		result.Lsh(result, 32)
		// Add the next uint32
		result.Add(result, big.NewInt(int64(v)))
	}

	return result
}

// Returns []byte represensation of an Image
// This function is used to define the PxlBytes field of an image in NewImage()
// Image -> big.Int -> fr.Element -> []byte
func ImageToBytes(img Image) []byte {
	var fe fr.Element
	imgBigInt := ImageToBigInt(img)
	fe.SetBigInt(imgBigInt)

	return fe.Marshal()
}

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
