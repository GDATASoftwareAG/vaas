// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// TokenResponse represents a response containing an access token.
type Detection struct {
	Engine   int    `json:"engine"`
	FileName string `json:"fileName"`
	Virus    string `json:"virus"`
}
