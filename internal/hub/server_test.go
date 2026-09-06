package hub

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func authenticatedRequest(method, path string, body *bytes.Reader) *http.Request {
	request := httptest.NewRequest(method, path, body)
	request.Header.Set("X-Tenant-ID", "tenant-1")
	request.Header.Set("X-Agent-ID", "agent-1")
	request.Header.Set("Authorization", "Bearer auth-token")
	return request
}

func TestHandlerRequiresIdentityAndBearerToken(t *testing.T) {
	handler := NewServer(Config{AuthToken: "auth-token", EnrollmentToken: "enroll-token"}).Handler()

	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent/config", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing identity status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/agent/config", nil)
	request.Header.Set("X-Tenant-ID", "tenant-1")
	request.Header.Set("X-Agent-ID", "agent-1")
	request.Header.Set("Authorization", "Bearer wrong")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestEnrollmentConfigMetricsAndHardening(t *testing.T) {
	server := NewServer(Config{AuthToken: "auth-token", EnrollmentToken: "enroll-token", CollectorIntervalSeconds: 15, LogLevel: "INFO", UpdateManifestURL: "https://hub.example/update.json"})
	handler := server.Handler()

	enrollment := bytes.NewBufferString(`{"enroll_token":"enroll-token","node_id":"node-1","agent_id":"agent-1","customer_id":42}`)
	request := authenticatedRequest(http.MethodPost, "/api/v1/agent/enroll", bytes.NewReader(enrollment.Bytes()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("enrollment status = %d, want %d", response.Code, http.StatusOK)
	}
	var enrollmentResponse EnrollmentResponse
	if err := json.NewDecoder(response.Body).Decode(&enrollmentResponse); err != nil {
		t.Fatal(err)
	}
	if enrollmentResponse.AgentID != "agent-1" || len(enrollmentResponse.MTLSSharedSecret) != 64 {
		t.Fatalf("unexpected enrollment response: %+v", enrollmentResponse)
	}

	request = authenticatedRequest(http.MethodGet, "/api/v1/agent/config", bytes.NewReader(nil))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.Len() == 0 {
		t.Fatalf("config response = %d, body = %q", response.Code, response.Body.String())
	}

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_ = json.NewEncoder(writer).Encode([]MetricEvent{{ID: "metric-1", Type: "system_metric", Timestamp: time.Now().UTC(), Data: json.RawMessage(`{"node_id":"node-1","cpu_usage_pct":12.5,"ram_usage_pct":22.5,"disk_usage_pct":30.5,"timestamp":"2026-09-06T12:00:00Z","status":"healthy"}`)}})
	_ = writer.Close()
	request = authenticatedRequest(http.MethodPost, "/api/v1/metrics", bytes.NewReader(compressed.Bytes()))
	request.Header.Set("Content-Encoding", "gzip")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || server.MetricsCount() != 1 {
		t.Fatalf("metrics response = %d, count = %d", response.Code, server.MetricsCount())
	}

	report := bytes.NewBufferString(`{"node_id":"node-1","job_id":"job-1","success":true,"message":"ok","open_issues":0,"cis_level_1_passed":true,"cis_open_issues":0}`)
	request = authenticatedRequest(http.MethodPost, "/api/v1/hardening/report", bytes.NewReader(report.Bytes()))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || server.ReportsCount() != 1 {
		t.Fatalf("report response = %d, count = %d", response.Code, server.ReportsCount())
	}
}
