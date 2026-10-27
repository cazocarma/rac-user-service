package transport

import (
	"github.com/cazocarma/rac-platform/documents"
	standingtransport "github.com/cazocarma/rac-platform/standing/transport"
	"io"
	"os"
	"strings"
)

// NewServiceClient validates the mounted credential before startup and shares
// the bounded client-credentials implementation used by standing. Provisioning
// controls the document audience/role; public requests cannot choose this ID.
func NewServiceClient(endpoint, tokenEndpoint, clientID, secretFile string, allowDEVHTTP bool) (*Client, error) {
	file, err := os.Open(secretFile)
	if err != nil {
		return nil, documents.ErrUnavailable
	}
	defer file.Close()
	secret, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(secret) > 4096 || len(strings.TrimSpace(string(secret))) < 32 {
		return nil, documents.ErrUnavailable
	}
	provider, err := standingtransport.CredentialsToken(tokenEndpoint, clientID, secretFile, allowDEVHTTP)
	if err != nil {
		return nil, documents.ErrUnavailable
	}
	return NewClient(endpoint, TokenProvider(provider), allowDEVHTTP)
}
