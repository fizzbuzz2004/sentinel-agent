package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"sentinel-agent/internal/identity"

	"github.com/denisbrodbeck/machineid" // Standard-Bibliothek für sichere Hardware-UUIDs in Go
)

type EnrollmentPayload struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	HardwareUUID    string `json:"hardware_uuid"`
	OSVersion       string `json:"os_version"`
}

type EnrollmentResponse struct {
	AgentID      string `json:"agent_id"`
	SharedSecret string `json:"mTLS_shared_secret"`
	Status       string `json:"status"`
}

// PerformInitialEnrollment registriert den Agenten beim Systemhaus-Hub
func PerformInitialEnrollment(hubURL string, enrollmentToken string) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	// Eindeutige, fälschungssichere Hardware-ID des Endgeräts ermitteln
	machineID, err := machineid.ProtectedID("sentinel-agent-dach")
	if err != nil {
		return fmt.Errorf("kritischer Fehler: Hardware-Fingerabdruck konnte nicht ermittelt werden: %v", err)
	}

	payload := EnrollmentPayload{
		EnrollmentToken: enrollmentToken,
		Hostname:        hostname,
		HardwareUUID:    machineID,
		OSVersion:       fmt.Sprintf("%s / %s", os.Getenv("GOOS"), os.Getenv("GOARCH")),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// HTTP-Client mit TLS-Härtung (Sicherheit Prio 1)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequest(http.MethodPost, hubURL+"/api/v1/agent/enroll", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("enrollment request konnte nicht erstellt werden: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	identityPath := os.Getenv("AGENT_IDENTITY_PATH")
	if identityPath == "" {
		identityPath = "/etc/sentinel-agent/identity.json"
	}
	if agentIdentity, identityErr := identity.LoadFromEnvironmentOrFile(identityPath); identityErr == nil {
		req.Header.Set("X-Tenant-ID", agentIdentity.TenantID)
		req.Header.Set("X-Agent-ID", agentIdentity.AgentID)
	}
	if authToken := os.Getenv("ENTERPRISE_AUTH_TOKEN"); authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("verbindung zum Systemhaus-Hub fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrollment vom Hub abgelehnt (HTTP Status: %d)", resp.StatusCode)
	}

	var enrollResp EnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return fmt.Errorf("antwort vom Hub konnte nicht verarbeitet werden: %v", err)
	}

	// Anmeldedaten sicher lokal auf dem Endpunkt persistieren (z.B. in geschützter Config-Datei)
	configData := fmt.Sprintf("AGENT_ID=%s\nSHARED_SECRET=%s\n", enrollResp.AgentID, enrollResp.SharedSecret)
	err = os.WriteFile("/etc/sentinel/agent.conf", []byte(configData), 0600) // Nur Root darf lesen!
	if err != nil {
		return fmt.Errorf("konfiguration konnte lokal nicht gespeichert werden: %v", err)
	}

	fmt.Println("Erfolgreich beim Systemhaus-Hub registriert. Agent-ID:", enrollResp.AgentID)
	return nil
}
