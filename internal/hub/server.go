package hub

import (
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	AuthToken                string
	EnrollmentToken          string
	CollectorIntervalSeconds int
	LogLevel                 string
	UpdateManifestURL        string
}

type Server struct {
	config  Config
	mu      sync.RWMutex
	agents  map[string]EnrollmentResponse
	metrics []MetricEvent
	reports []HardeningReport
}

type EnrollmentRequest struct {
	EnrollToken string          `json:"enroll_token"`
	NodeID      string          `json:"node_id"`
	AgentID     string          `json:"agent_id"`
	CustomerID  json.RawMessage `json:"customer_id"`
}

type EnrollmentResponse struct {
	AgentID          string `json:"agent_id"`
	MTLSSharedSecret string `json:"mTLS_shared_secret"`
	Status           string `json:"status"`
}

type MetricEvent struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
}

type HardeningReport struct {
	NodeID          string `json:"node_id"`
	JobID           string `json:"job_id"`
	Success         bool   `json:"success"`
	Message         string `json:"message"`
	OpenIssues      int    `json:"open_issues"`
	CISLevel1Passed bool   `json:"cis_level_1_passed"`
	CISOpenIssues   int    `json:"cis_open_issues"`
}

func NewServer(config Config) *Server {
	if config.CollectorIntervalSeconds <= 0 {
		config.CollectorIntervalSeconds = 30
	}
	return &Server{config: config, agents: make(map[string]EnrollmentResponse)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/enroll", s.handleEnroll)
	mux.HandleFunc("/api/v1/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/agent/config", s.handleConfig)
	mux.HandleFunc("/api/v1/hardening/report", s.handleHardeningReport)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticate(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("X-Tenant-ID")) == "" || strings.TrimSpace(r.Header.Get("X-Agent-ID")) == "" {
		http.Error(w, "missing tenant or agent identity", http.StatusBadRequest)
		return false
	}
	if s.config.AuthToken == "" || r.Header.Get("Authorization") != "Bearer "+s.config.AuthToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request EnrollmentRequest
	if err := decodeJSON(r, &request); err != nil || request.EnrollToken == "" || request.NodeID == "" || request.AgentID == "" || len(request.CustomerID) == 0 {
		http.Error(w, "invalid enrollment payload", http.StatusBadRequest)
		return
	}
	if s.config.EnrollmentToken == "" || request.EnrollToken != s.config.EnrollmentToken {
		http.Error(w, "invalid enrollment token", http.StatusUnauthorized)
		return
	}
	secret, err := randomSecret()
	if err != nil {
		http.Error(w, "could not create enrollment secret", http.StatusInternalServerError)
		return
	}
	response := EnrollmentResponse{AgentID: request.AgentID, MTLSSharedSecret: secret, Status: "enrolled"}
	s.mu.Lock()
	s.agents[request.AgentID] = response
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Encoding") != "gzip" {
		http.Error(w, "gzip content encoding required", http.StatusUnsupportedMediaType)
		return
	}
	reader, err := gzip.NewReader(http.MaxBytesReader(w, r.Body, 10<<20))
	if err != nil {
		http.Error(w, "invalid gzip payload", http.StatusBadRequest)
		return
	}
	defer reader.Close()
	var events []MetricEvent
	if err := decodeReader(reader, &events); err != nil || len(events) == 0 {
		http.Error(w, "invalid metrics payload", http.StatusBadRequest)
		return
	}
	for _, event := range events {
		if err := validateMetricEvent(event); err != nil {
			http.Error(w, "unsupported metric type", http.StatusBadRequest)
			return
		}
	}
	s.mu.Lock()
	s.metrics = append(s.metrics, events...)
	s.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	response := map[string]any{"collector_interval_seconds": s.config.CollectorIntervalSeconds, "log_level": s.config.LogLevel}
	if s.config.UpdateManifestURL != "" {
		response["update"] = map[string]string{"manifest_url": s.config.UpdateManifestURL}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleHardeningReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var report HardeningReport
	if err := decodeJSON(r, &report); err != nil || report.NodeID == "" || report.JobID == "" {
		http.Error(w, "invalid hardening report", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.reports = append(s.reports, report)
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func decodeJSON(r *http.Request, target any) error {
	return decodeReader(io.LimitReader(r.Body, 10<<20), target)
}

func decodeReader(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomSecret() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate enrollment secret: %w", err)
	}
	return hex.EncodeToString(secret), nil
}

// SignCommand creates the value expected in X-Command-Signature on the agent.
func SignCommand(command, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(command))
	return hex.EncodeToString(mac.Sum(nil))
}

func validateMetricEvent(event MetricEvent) error {
	if event.ID == "" || event.Timestamp.IsZero() || len(event.Data) == 0 {
		return errors.New("metric wrapper is incomplete")
	}
	if event.Type != "system_metric" && event.Type != "fim_alert" {
		return errors.New("unsupported metric type")
	}
	var data map[string]any
	if err := json.Unmarshal(event.Data, &data); err != nil || data["node_id"] == nil || data["timestamp"] == nil {
		return errors.New("metric data is incomplete")
	}
	if event.Type == "system_metric" {
		for _, field := range []string{"cpu_usage_pct", "ram_usage_pct", "disk_usage_pct", "status"} {
			if data[field] == nil {
				return errors.New("system metric data is incomplete")
			}
		}
	} else if data["file_path"] == nil || data["event"] == nil {
		return errors.New("fim alert data is incomplete")
	}
	return nil
}

func TLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load hub certificate: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid client CA certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: clientCAs, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, nil
}

func (s *Server) MetricsCount() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.metrics) }
func (s *Server) ReportsCount() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.reports) }

func (s *Server) SignAgentCommand(agentID, command string) (string, error) {
	s.mu.RLock()
	enrollment, ok := s.agents[agentID]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("agent %q is not enrolled", agentID)
	}
	return SignCommand(command, enrollment.MTLSSharedSecret), nil
}
