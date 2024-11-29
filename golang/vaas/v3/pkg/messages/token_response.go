// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// TokenResponse represents a response containing an access token.
type TokenResponse struct {
	Accesstoken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// TokenErrorResponse represents an error response containing an error message.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
