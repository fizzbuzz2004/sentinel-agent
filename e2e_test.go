package agent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinel-agent/internal/agent"
	"sentinel-agent/internal/buffer"
	"sentinel-agent/internal/config"
	"sentinel-agent/internal/hub"

	"go.uber.org/goleak"
)

const (
	testAuthToken   = "e2e-auth-token"
	testEnrollToken = "e2e-enroll-token"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func newTestClient(t *testing.T, endpoint, tenant, agentID string, retry agent.RetryPolicy) *agent.Client {
	t.Helper()
	client, err := agent.NewClient(agent.ClientConfig{
		TenantID: tenant, AgentID: agentID, AuthToken: testAuthToken,
		AllowInsecureHTTP: true, Timeout: 3 * time.Second, Retry: retry,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func validMetric(id, nodeID string, sequence int) hub.MetricEvent {
	data, _ := json.Marshal(map[string]any{
		"node_id": nodeID, "timestamp": time.Now().UTC(), "cpu_usage_pct": 10,
		"ram_usage_pct": 20, "disk_usage_pct": 30, "status": fmt.Sprintf("seq-%d", sequence),
	})
	return hub.MetricEvent{ID: id, Type: "system_metric", Data: data, Timestamp: time.Now().UTC()}
}

func TestE2EGoldenPathAndSecurityDrops(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	backend := hub.NewServer(hub.Config{AuthToken: testAuthToken, EnrollmentToken: testEnrollToken, CollectorIntervalSeconds: 1, LogLevel: "DEBUG"})
	server := httptest.NewServer(backend.Handler())
	t.Cleanup(server.Close)
	client := newTestClient(t, server.URL, "tenant-e2e", "agent-e2e", agent.RetryPolicy{Attempts: 1})

	enrollment, err := client.Enroll(context.Background(), server.URL, testEnrollToken, "node-e2e", "agent-e2e", 42)
	if err != nil || enrollment.Status != "enrolled" || len(enrollment.SharedSecret) != 64 {
		t.Fatalf("enrollment failed: response=%+v error=%v", enrollment, err)
	}

	store := config.NewStore(config.RuntimeConfig{CollectorInterval: time.Minute, LogLevel: slog.LevelInfo})
	level := new(slog.LevelVar)
	poller, err := config.NewPoller(server.URL+"/api/v1/agent/config", 10*time.Millisecond, store, level, func() (*http.Client, error) { return client.HTTPClient(), nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go poller.Run(ctx)
	t.Cleanup(cancel)
	if !waitFor(t, time.Second, func() bool { return store.Load().CollectorInterval == time.Second }) {
		t.Fatalf("config was not polled: %+v", store.Load())
	}

	compressed, err := agent.CompressJSON([]hub.MetricEvent{validMetric("metric-e2e", "node-e2e", 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendCompressed(context.Background(), server.URL+"/api/v1/metrics", compressed); err != nil {
		t.Fatal(err)
	}

	command := "/usr/bin/ansible-playbook /etc/sentinel/playbooks/hardening.yml"
	commandHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Command-Signature") != hub.SignCommand(command, enrollment.SharedSecret) {
			slog.Warn("security event: invalid command signature", "component", "agent", "event", "security_drop", "reason", "invalid_command_signature")
			http.Error(w, "invalid command signature", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	commandRequest := httptest.NewRequest(http.MethodPost, "/api/v1/commands", nil)
	commandRequest.Header.Set("X-Command-Signature", hub.SignCommand(command, enrollment.SharedSecret))
	commandResponse := httptest.NewRecorder()
	commandHandler.ServeHTTP(commandResponse, commandRequest)
	if commandResponse.Code != http.StatusAccepted {
		t.Fatalf("signed command status = %d", commandResponse.Code)
	}
	commandRequest.Header.Set("X-Command-Signature", "00bad")
	commandResponse = httptest.NewRecorder()
	commandHandler.ServeHTTP(commandResponse, commandRequest)
	if commandResponse.Code != http.StatusUnauthorized {
		t.Fatalf("invalid command status = %d", commandResponse.Code)
	}

	badTokenRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/config", nil)
	badTokenRequest.Header.Set("X-Tenant-ID", "tenant-e2e")
	badTokenRequest.Header.Set("X-Agent-ID", "agent-e2e")
	badTokenRequest.Header.Set("Authorization", "Bearer mutated-token")
	badTokenResponse, err := http.DefaultClient.Do(badTokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	badTokenResponse.Body.Close()
	if badTokenResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mutated bearer status = %d", badTokenResponse.StatusCode)
	}
	foreignIdentityRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/config", nil)
	foreignIdentityRequest.Header.Set("X-Tenant-ID", "foreign-tenant")
	foreignIdentityRequest.Header.Set("X-Agent-ID", "agent-e2e")
	foreignIdentityRequest.Header.Set("Authorization", "Bearer "+testAuthToken)
	foreignIdentityResponse, err := http.DefaultClient.Do(foreignIdentityRequest)
	if err != nil {
		t.Fatal(err)
	}
	foreignIdentityResponse.Body.Close()
	if foreignIdentityResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign tenant status = %d", foreignIdentityResponse.StatusCode)
	}

	if backend.MetricsCount() != 1 || !strings.Contains(logs.String(), "invalid_bearer_token") || !strings.Contains(logs.String(), "identity_mismatch") || !strings.Contains(logs.String(), "invalid_command_signature") {
		t.Fatalf("golden path/security observations incomplete: metrics=%d logs=%s", backend.MetricsCount(), logs.String())
	}
}

func TestE2ERejectsExpiredAndForeignMTLSCertificates(t *testing.T) {
	caCert, caKey := mustCA(t, "e2e-ca")
	serverCert, _ := mustSignedCert(t, caCert, caKey, "localhost", false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	clientCert, clientKey := mustSignedCert(t, caCert, caKey, "agent-e2e", true, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	foreignCA, foreignKey := mustCA(t, "foreign-ca")
	foreignCert, foreignClientKey := mustSignedCert(t, foreignCA, foreignKey, "foreign-agent", true, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	expiredCert, expiredKey := mustSignedCert(t, caCert, caKey, "expired-agent", true, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))

	server := httptest.NewUnstartedServer(hub.NewServer(hub.Config{AuthToken: testAuthToken, EnrollmentToken: testEnrollToken}).Handler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certPool(caCert), MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)

	testMTLSClient(t, server.URL, caCert, clientCert, clientKey, true)
	testMTLSClient(t, server.URL, caCert, foreignCert, foreignClientKey, false)
	certFile, keyFile := writePair(t, expiredCert, expiredKey)
	if _, err := agent.NewClient(agent.ClientConfig{TenantID: "tenant-e2e", AgentID: "expired-agent", AuthToken: testAuthToken, CertFile: certFile, KeyFile: keyFile, CAFile: caFile(t, caCert)}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal("expired client certificate was accepted")
	}
}

func testMTLSClient(t *testing.T, endpoint string, ca *x509.Certificate, cert tls.Certificate, key *ecdsa.PrivateKey, wantSuccess bool) {
	t.Helper()
	certFile, keyFile := writePair(t, cert, key)
	client, err := agent.NewClient(agent.ClientConfig{TenantID: "tenant-e2e", AgentID: "agent-e2e", AuthToken: testAuthToken, CertFile: certFile, KeyFile: keyFile, CAFile: caFile(t, ca), Retry: agent.RetryPolicy{Attempts: 1}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if wantSuccess {
		requestEndpoint := strings.Replace(endpoint, "127.0.0.1", "localhost", 1)
		if _, err := client.Enroll(context.Background(), requestEndpoint, testEnrollToken, "node-e2e", "agent-e2e", 42); err != nil {
			t.Fatal(err)
		}
	}
	response, err := client.HTTPClient().Get(strings.Replace(endpoint, "127.0.0.1", "localhost", 1) + "/api/v1/agent/config")
	if wantSuccess {
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("valid mTLS request failed: status=%v error=%v", response, err)
		}
		response.Body.Close()
	} else if err == nil {
		response.Body.Close()
		t.Fatal("foreign certificate completed TLS handshake")
	}
}

func TestE2ESpoolBackpressureAndChronologicalRecovery(t *testing.T) {
	var outage atomic.Bool
	backend := hub.NewServer(hub.Config{AuthToken: testAuthToken, EnrollmentToken: testEnrollToken})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if outage.Load() {
			http.Error(w, "hub unavailable", http.StatusServiceUnavailable)
			return
		}
		backend.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server.URL, "tenant-load", "agent-load", agent.RetryPolicy{Attempts: 1})
	if _, err := client.Enroll(context.Background(), server.URL, testEnrollToken, "node-load", "agent-load", 42); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	spool, err := buffer.NewDiskBuffer(filepath.Join(dir, "spool.bin"), 100, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	for sequence := 0; sequence < 25; sequence++ {
		var data map[string]any
		if err := json.Unmarshal(validMetric(fmt.Sprintf("spool-%02d", sequence), "node-load", sequence).Data, &data); err != nil {
			t.Fatal(err)
		}
		if err := spool.Enqueue("system_metric", data); err != nil {
			t.Fatal(err)
		}
	}
	outage.Store(true)
	if err := spool.FlushCompress(context.Background(), func(ctx context.Context, payload []byte) error {
		return client.SendCompressed(ctx, server.URL+"/api/v1/metrics", payload)
	}); err == nil {
		t.Fatal("flush succeeded during hub outage")
	}
	outage.Store(false)
	if err := spool.FlushCompress(context.Background(), func(ctx context.Context, payload []byte) error {
		return client.SendCompressed(ctx, server.URL+"/api/v1/metrics", payload)
	}); err != nil {
		t.Fatal(err)
	}
	events := backend.MetricsSnapshot()
	if len(events) != 25 {
		t.Fatalf("recovered events = %d, want 25", len(events))
	}
	for sequence, event := range events {
		var data map[string]any
		if err := json.Unmarshal(event.Data, &data); err != nil {
			t.Fatal(err)
		}
		if data["status"] != fmt.Sprintf("seq-%d", sequence) {
			t.Fatalf("event %d status = %v, order was not preserved", sequence, data["status"])
		}
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return condition()
}

func mustCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mustSignedCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, client bool, notBefore, notAfter time.Time) (tls.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{commonName}, NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func certPool(ca *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

func caFile(t *testing.T, ca *x509.Certificate) string {
	return writeFile(t, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
}

func writePair(t *testing.T, cert tls.Certificate, key *ecdsa.PrivateKey) (string, string) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})), writeFile(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func writeFile(t *testing.T, name string, data []byte) string {
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
