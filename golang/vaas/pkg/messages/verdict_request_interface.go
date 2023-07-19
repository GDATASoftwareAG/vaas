package messages

type Kind string

const (
	VerdictRequestKind       Kind = "VerdictRequest"
	VerdictRequestForURLKind Kind = "VerdictRequestForUrl"
)

type VerdictRequest interface {
	GetGUID() string
}
