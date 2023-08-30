// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// Kind represents the type of message.
type Kind string

// VerdictRequestKind and VerdictRequestForURLKind are kinds of VerdictRequest.
const (
	VerdictRequestKind       Kind = "VerdictRequest"
	VerdictRequestForURLKind Kind = "VerdictRequestForUrl"
)

// VerdictRequest is an interface for various types of verdict requests.
type VerdictRequest interface {
	GetGUID() string
}
