// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// TokenResponse represents a response containing an access token.
type TokenResponse struct {
	Accesstoken string `json:"access_token"`
}
