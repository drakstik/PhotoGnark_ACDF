package main

import (
	"github.com/drakstik/PhotoGnark_ACDF/examples"
	"github.com/drakstik/PhotoGnark_ACDF/photoproof"
)

func main() {
	photo, _ := examples.TakePhoto_Example()
	examples.EditPhoto_Example(photo, photoproof.Identity_Tr{}, photoproof.Identity_Tr_Params{})
}
