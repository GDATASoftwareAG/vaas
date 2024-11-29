package messages

import (
	"encoding/json"
	"errors"
)

type ProblemDetails struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (p *ProblemDetails) UnmarshalJSON(data []byte) error {
	var problemDetails ProblemDetails
	err := json.Unmarshal(data, &problemDetails)
	if err != nil {
		return err
	}
	if problemDetails.Type == "" {
		return errors.New("empty type in ProblemDetails")
	}
	return nil
}
