package reverse

import (
	"net/http"

	"github.com/scionproto/scion/pkg/snet"
	"go.uber.org/zap"
)

type Detector struct {
	logger *zap.Logger
}

func NewDetector(logger *zap.Logger) Detector {
	return Detector{
		logger: logger,
	}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (d Detector) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	d.logger.Debug("Checking for scion traffic.",
		zap.String("remote-address", r.RemoteAddr))
	if _, err := snet.ParseUDPAddr(r.RemoteAddr); err == nil {
		r.Header.Add("X-SCION", "on")
		r.Header.Add("X-SCION-Remote-Addr", r.RemoteAddr)
	} else {
		r.Header.Add("X-SCION", "off")
	}
	return nil
}
