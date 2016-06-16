package tlsdefaults

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/getlantern/keyman"
)

// Listen opens a TLS listener at the given address using the private key and
// certificate PEM files at the given paths. If no files exists, it creates a
// new key and self-signed certificate at those locations.
func Listen(addr, pkfile, certfile string) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("Unable to listen for connections at %s: %s\n", addr, err)
	}

	return NewListener(l, pkfile, certfile)
}

// NewListener creates a TLS listener based on the given listener using the
// private key and certificate PEM files at the given paths. If no files exists,
// it creates a new key and self-signed certificate at those locations.
func NewListener(l net.Listener, pkfile, certfile string) (net.Listener, error) {
	addr := l.Addr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("Unable to split host and port for %v: %v\n", addr, err)
	}

	cert, err := keyman.KeyPairFor(host, pkfile, certfile)
	if err != nil {
		return nil, err
	}

	return tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{cert},
	}), nil
}
