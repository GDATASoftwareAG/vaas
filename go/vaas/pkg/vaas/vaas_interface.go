package vaas

import (
	"hash"
	"net/url"

	msg "vaas/pkg/messages"
)

type IVaaS interface {
	Connect(token string)
	ForUrl(uri url.URL)
	ForSha256(sha256 hash.Hash)
	ForFile(path string)
	ForSha256List(sha256List []hash.Hash)
	ForFileList(fileList []string) msg.VaasVerdict
}
