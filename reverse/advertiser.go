package reverse

import (
	"net/http"

	"github.com/scionproto/scion/pkg/snet"
	"go.uber.org/zap"
)

type Advertiser struct {
	StrictScion string `json:"Strict-SCION,omitempty"`

	logger *zap.Logger
}

func NewAdvertiser(logger *zap.Logger, strictScion string) Advertiser {
	return Advertiser{
		StrictScion: strictScion,
		logger:      logger,
	}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (a Advertiser) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	a.logger.Debug("Checking for scion traffic.",
		zap.String("remote-address", r.RemoteAddr))

	if _, err := snet.ParseUDPAddr(r.RemoteAddr); err != nil {
		if w.Header().Get("Strict-SCION") == "" {
			w.Header().Set("Strict-SCION", a.StrictScion)
		}
	}
	return nil
}
