package messages

type Kind string

const (
	VerdictRequestKind       Kind = "VerdictRequest"
	VerdictRequestForUrlKind Kind = "VerdictRequestForUrl"
)

type VerdictRequest interface {
	GetGuid() string
}
