package messages

type ProblemDetails struct {
	Type   string `json:"type" validate:"required"`
	Detail string `json:"detail"`
}
