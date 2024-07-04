// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// Verdict represents different verdict outcomes.
type Verdict string

// Verdict outcomes.
const (
	Clean     Verdict = "Clean"
	Unknown   Verdict = "Unknown"
	Malicious Verdict = "Malicious"
	Pup       Verdict = "Pup"
	Error     Verdict = "Error"
)
