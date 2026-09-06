package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"sentinel-agent/internal/hardening"
	"sentinel-agent/internal/identity"
)

type ExecutionResponse struct {
	JobID   string `json:"job_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type HardeningReport struct {
	NodeID          string    `json:"node_id"`
	JobID           string    `json:"job_id"`
	Success         bool      `json:"success"`
	Message         string    `json:"message"`
	OpenIssues      int       `json:"open_issues"`
	CISLevel1Passed bool      `json:"cis_level_1_passed"`
	CISOpenIssues   int       `json:"cis_open_issues"`
	CompletedAt     time.Time `json:"completed_at"`
}

const (
	ansibleBinary   = "/usr/bin/ansible-playbook"
	ansiblePlaybook = "/etc/sentinel/playbooks/hardening.yml"
)

func RunAnsiblePlaybook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	secret := os.Getenv("REMOTE_HARDENING_HMAC_SECRET")
	if secret == "" {
		http.Error(w, "remote hardening is not configured", http.StatusServiceUnavailable)
		return
	}
	signature := r.Header.Get("X-Command-Signature")
	runner := NewSecureRunner(secret)
	if !runner.VerifySignature(ansibleBinary+" "+ansiblePlaybook, signature) {
		slog.Warn("Sicherheitsereignis: ungültige HMAC-Signatur für Remote-Hardening verworfen", "component", "security", "event", "invalid_command_signature")
		http.Error(w, "invalid command signature", http.StatusUnauthorized)
		return
	}

	jobID := fmt.Sprintf("job-%d", time.Now().UnixNano())
	go func(id string) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		slog.Info("Starte asynchronen Härtungsprozess", "job_id", id)
		output, err := runner.ExecuteSandboxed(ctx, ansibleBinary, []string{ansiblePlaybook}, signature)
		success := true
		msg := "Hardening successfully applied"
		openIssues := 0
		if err != nil {
			slog.Error("Ansible Härtung fehlgeschlagen", "job_id", id, "error", err, "output", string(output))
			success = false
			msg = fmt.Sprintf("Execution error: %v", err)
			openIssues = 1
		} else {
			slog.Info("Ansible Härtung erfolgreich abgeschlossen", "job_id", id)
		}
		cisPassed, cisIssues := hardening.ValidateCISLevel1(ctx)
		if !cisPassed {
			success = false
			openIssues += cisIssues
			msg += "; CIS Level 1 validation found open issues"
		}
		reportBackToHub(HardeningReport{
			NodeID:          os.Getenv("NODE_ID"),
			JobID:           id,
			Success:         success,
			Message:         msg,
			OpenIssues:      openIssues,
			CISLevel1Passed: cisPassed,
			CISOpenIssues:   cisIssues,
			CompletedAt:     time.Now().UTC(),
		})
	}(jobID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ExecutionResponse{JobID: jobID, Status: "accepted", Message: "Hardening process queued and running in background"})
}

func reportBackToHub(report HardeningReport) {
	hubURL := os.Getenv("HUB_CALLBACK_URL")
	if hubURL == "" {
		hubURL = "https://10.0.0.1:8443/api/v1/hardening/report"
	}
	if report.NodeID == "" {
		report.NodeID = "unknown-node"
	}
	data, err := json.Marshal(report)
	if err != nil {
		slog.Error("Fehler beim Marshalling des Reports", "error", err)
		return
	}

	certPath := getEnvOrDefault("AGENT_CERT_PATH", "/etc/sentinel/certs/agent.crt")
	keyPath := getEnvOrDefault("AGENT_KEY_PATH", "/etc/sentinel/certs/agent.key")
	caPath := getEnvOrDefault("CA_CERT_PATH", "/etc/sentinel/certs/ca.crt")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		slog.Error("mTLS Zertifikat konnte für Callback nicht geladen werden", "error", err, "cert_path", certPath, "key_path", keyPath)
		return
	}
	if len(cert.Certificate) == 0 {
		slog.Error("mTLS Zertifikat enthält keine Zertifikatskette", "cert_path", certPath)
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		slog.Error("mTLS Zertifikat ist nicht parsebar", "error", err, "cert_path", certPath)
		return
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		slog.Error("mTLS Zertifikat ist abgelaufen oder noch nicht gültig", "cert_path", certPath, "not_before", leaf.NotBefore, "not_after", leaf.NotAfter)
		return
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		slog.Error("CA Zertifikat Ladefehler beim Callback", "error", err, "ca_path", caPath)
		return
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		slog.Error("CA Zertifikat konnte nicht geladen werden", "ca_path", caPath)
		return
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool, MinVersion: tls.VersionTLS13}}, Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodPost, hubURL, bytes.NewBuffer(data))
	if err != nil {
		slog.Error("Fehler beim Erstellen des Requests", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	identityPath := getEnvOrDefault("AGENT_IDENTITY_PATH", "/etc/sentinel-agent/identity.json")
	if agentIdentity, identityErr := identity.LoadFromEnvironmentOrFile(identityPath); identityErr == nil {
		req.Header.Set("X-Tenant-ID", agentIdentity.TenantID)
		req.Header.Set("X-Agent-ID", agentIdentity.AgentID)
	}
	if authToken := os.Getenv("ENTERPRISE_AUTH_TOKEN"); authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Konnte Hardening-Status nicht an Hub senden", "error", err, "hub_url", hubURL)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		slog.Error("Hub hat Hardening-Status abgelehnt", "status_code", resp.StatusCode, "hub_url", hubURL)
		return
	}
	slog.Info("Hardening-Status erfolgreich an Hub gemeldet", "status_code", resp.StatusCode)
}

func getEnvOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
