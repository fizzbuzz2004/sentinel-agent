package agent

import (
	"crypto/ed25519"
	"net/http"

	coreupdater "sentinel-agent/internal/updater"
)

// NewUpdateManager exposes the signed update manager through the agent client package.
func NewUpdateManager(client *http.Client, publicKey ed25519.PublicKey, target string, headers http.Header) (*coreupdater.Updater, error) {
	return coreupdater.NewWithHeaders(client, publicKey, target, headers)
}
