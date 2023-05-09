package messages

type Verdict string

const (
	Clean     Verdict = "Clean"
	Unknown   Verdict = "Unknown"
	Malicious Verdict = "Malicious"
	Pup       Verdict = "Pup"
	Error     Verdict = "Error"
)
