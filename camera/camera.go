package camera

import (
	"github.com/drakstik/PhotoGnark_ACDF/photoproof"
)

// This object simulates a secure camera
type Camera struct {
	Admin        photoproof.User
	Photographs  []photoproof.Photograph
	ProvingKey   photoproof.ProverKeys
	VerifyingKey photoproof.VerifierKeys
}
