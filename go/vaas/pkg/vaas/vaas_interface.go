package vaas

import (
	"hash"
	"net/url"

	msg "vaas/pkg/messages"
)

type IVaaS interface {
	Connect(token string)
	ForUrl(uri url.URL) msg.VaasVerdict
	ForSha256(sha256 hash.Hash) msg.VaasVerdict
	ForFile(path string) msg.VaasVerdict
	ForSha256List(sha256List []hash.Hash) []msg.VaasVerdict
	ForFileList(fileList []string) []msg.VaasVerdict
}
