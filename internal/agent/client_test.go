package agent

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinel-agent/internal/executor"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testClient(t *testing.T, transport http.RoundTripper, retry RetryPolicy) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		TenantID: "tenant-1", AgentID: "agent-1", AuthToken: "token-1",
		HTTPClient: &http.Client{Transport: transport}, Retry: retry,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestClientInjectsHeadersAndReusesTransport(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Tenant-ID") != "tenant-1" || r.Header.Get("X-Agent-ID") != "agent-1" || r.Header.Get("Authorization") != "Bearer token-1" {
			t.Errorf("required headers missing: %v", r.Header)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 1
	client := testClient(t, transport, RetryPolicy{Attempts: 1})
	for range 2 {
		if err := client.SendCompressed(context.Background(), server.URL, []byte("gzip")); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want 2", requests.Load())
	}
}

func TestClientRetriesTemporaryHubFailureWithJitter(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	var delays []time.Duration
	client := testClient(t, http.DefaultTransport, RetryPolicy{
		Attempts: 4, BaseDelay: time.Second, MaxDelay: 10 * time.Second,
		Random: func(max int64) int64 { return max / 2 },
		Sleep:  func(_ context.Context, delay time.Duration) error { delays = append(delays, delay); return nil },
	})
	if err := client.SendCompressed(context.Background(), server.URL, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 || len(delays) != 2 {
		t.Fatalf("attempts=%d delays=%d", attempts.Load(), len(delays))
	}
	if delays[1] <= delays[0] {
		t.Fatalf("jitter backoff did not grow: %v", delays)
	}
}

func TestClientRecoversFromNetworkInterruptionAndReEnrolls(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"agent_id":"agent-1","mTLS_shared_secret":"secret-1","status":"enrolled"}`)
	}))
	defer server.Close()
	var interrupted atomic.Bool
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if interrupted.CompareAndSwap(false, true) {
			return nil, io.ErrUnexpectedEOF
		}
		return http.DefaultTransport.RoundTrip(request)
	})
	client := testClient(t, transport, RetryPolicy{Attempts: 3, Sleep: func(context.Context, time.Duration) error { return nil }, Random: func(int64) int64 { return 0 }})
	if _, err := client.Enroll(context.Background(), server.URL, "enroll-token", "node-1", "agent-1", 42); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Enroll(context.Background(), server.URL, "enroll-token", "node-1", "agent-1", 42); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("successful enrollment requests = %d, want 2", requests.Load())
	}
}

func TestCompressJSONProducesHubReadableGZIP(t *testing.T) {
	payload := []map[string]any{{"id": "event-1", "type": "fim_alert", "data": map[string]any{"node_id": "node-1", "file_path": "/etc/example", "event": "MODIFIED", "timestamp": time.Now().UTC()}}}
	compressed, err := CompressJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(strings.NewReader(string(compressed)))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var events []map[string]any
	if err := json.Unmarshal(decoded, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0]["id"] != "event-1" {
		t.Fatalf("decoded payload = %s", decoded)
	}
}

func TestRemoteHardeningRejectsInvalidHMAC(t *testing.T) {
	t.Setenv("REMOTE_HARDENING_HMAC_SECRET", "test-secret")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hardening", nil)
	request.Header.Set("X-Command-Signature", "invalid")
	response := httptest.NewRecorder()
	executor.RunAnsiblePlaybook(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	mac := hmac.New(sha256.New, []byte("test-secret"))
	_, _ = mac.Write([]byte("/usr/bin/ansible-playbook /etc/sentinel/playbooks/hardening.yml"))
	valid := hex.EncodeToString(mac.Sum(nil))
	if !executor.NewSecureRunner("test-secret").VerifySignature("/usr/bin/ansible-playbook /etc/sentinel/playbooks/hardening.yml", valid) {
		t.Fatal("expected valid HMAC")
	}
}
