package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"
)

type CertificateWatcher struct {
	path        string
	keyPath     string
	renewBefore time.Duration
	interval    time.Duration
	renew       func(context.Context) error
	lastRenewal time.Time
}

func NewCertificateWatcher(path, keyPath string, renewBefore, interval time.Duration, renew func(context.Context) error) (*CertificateWatcher, error) {
	if path == "" || keyPath == "" || renew == nil {
		return nil, fmt.Errorf("certificate watcher requires path, key path, and renewal callback")
	}
	if renewBefore <= 0 {
		renewBefore = 72 * time.Hour
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &CertificateWatcher{path: path, keyPath: keyPath, renewBefore: renewBefore, interval: interval, renew: renew}, nil
}

func (w *CertificateWatcher) Run(ctx context.Context) {
	w.check(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.check(ctx)
		}
	}
}

func (w *CertificateWatcher) check(ctx context.Context) {
	certificate, err := loadLeafCertificate(w.path, w.keyPath)
	if err != nil {
		slog.Error("mTLS-Zertifikat konnte nicht geprüft werden", "component", "security", "event", "certificate_check_failed", "error", err)
		return
	}
	if time.Until(certificate.NotAfter) > w.renewBefore || certificate.NotAfter.Equal(w.lastRenewal) {
		return
	}
	if err := w.renew(ctx); err != nil {
		slog.Error("mTLS-Re-Enrollment fehlgeschlagen", "component", "security", "event", "certificate_renewal_failed", "error", err)
		return
	}
	w.lastRenewal = certificate.NotAfter
	slog.Info("mTLS-Re-Enrollment angestoßen", "component", "security", "event", "certificate_renewal_requested", "expires_at", certificate.NotAfter.UTC().Format(time.RFC3339))
}

func loadLeafCertificate(path, keyPath string) (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(path, keyPath)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	return x509.ParseCertificate(pair.Certificate[0])
}
