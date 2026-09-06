package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCertificateWatcherRequestsRenewalBeforeExpiry(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "agent.crt")
	keyPath := filepath.Join(directory, "agent.key")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: new(big.Int).SetInt64(1), Subject: pkix.Name{CommonName: "agent"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{SerialNumber: new(big.Int).SetInt64(1), Subject: pkix.Name{CommonName: "agent"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM := func(path string, block *pem.Block) error { return os.WriteFile(path, pem.EncodeToMemory(block), 0600) }
	if err := writePEM(certPath, &pem.Block{Type: "CERTIFICATE", Bytes: certificate}); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(keyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	var renewals atomic.Int32
	watcher, err := NewCertificateWatcher(certPath, keyPath, 2*time.Hour, time.Hour, func(context.Context) error { renewals.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	watcher.check(context.Background())
	if renewals.Load() != 1 {
		t.Fatalf("renewals = %d, want 1", renewals.Load())
	}
	watcher.check(context.Background())
	if renewals.Load() != 1 {
		t.Fatalf("renewal repeated without certificate change: %d", renewals.Load())
	}
}
