package vaas

import (
	msg "vaas/pkg/messages"
)

type IVaaS interface {
	Connect(token string) error
	Authenticate(token string) error
	ForUrl(uri string) (msg.VaasVerdict, error)
	ForSha256(sha256 string) (msg.VaasVerdict, error)
	ForFile(path string) (msg.VaasVerdict, error)
	ForSha256List(sha256List []string) ([]msg.VaasVerdict, error)
	ForFileList(fileList []string) ([]msg.VaasVerdict, error)
}
