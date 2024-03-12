// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// VaasVerdict represents the verdict information returned by the VaaS server.
type VaasVerdict struct {
	Verdict    Verdict
	Sha256     string
	ErrMsg     string
	Detections []Detection
	LibMagic   LibMagic
}
