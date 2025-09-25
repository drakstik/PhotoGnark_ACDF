package examples

import (
	"fmt"

	"github.com/drakstik/PhotoGnark_ACDF/camera"
	"github.com/drakstik/PhotoGnark_ACDF/photoproof"
)

func NewCamera_Example() camera.Camera {
	return camera.NewCamera() // Get a new camera, run generator
}

// Example for a new camera and taking a photo
func TakePhoto_Example() (photoproof.Photograph, error) {
	cam := NewCamera_Example()                 // Get a new camera, run generator
	photo, err := cam.TakePhotograph("random") // Take a picture and prove it
	if err != nil {
		fmt.Println("Error while taking a photograph\n" + err.Error())
		return photoproof.Photograph{}, err
	}

	return photo, err
}

func EditPhoto_Example(photo photoproof.Photograph, tr photoproof.Transformation, params photoproof.Parameters) {

	editor := photoproof.NewUser()

	editor.Edit(photo, tr, params)
}
