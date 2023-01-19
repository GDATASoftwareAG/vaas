package messages

import (
	"hash"
)

type VaasVerdict struct {
	Verdict   Verdict 	`json:"verdict"`
	Sha256    hash.Hash `json:"sha256"`
	SessionId string 	`json:"session_id"`
}
