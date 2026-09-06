package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const maxBinarySize int64 = 256 * 1024 * 1024

type UpdateManifest struct {
	Version   string `json:"version"`
	BinaryURL string `json:"binary_url"`
	Checksum  string `json:"checksum"`
	Signature string `json:"signature"`
}

type Updater struct {
	client    *http.Client
	publicKey ed25519.PublicKey
	target    string
	headers   http.Header
	mu        sync.Mutex
	backup    string
}

func New(client *http.Client, publicKey ed25519.PublicKey, target string) (*Updater, error) {
	return NewWithHeaders(client, publicKey, target, nil)
}

func NewWithHeaders(client *http.Client, publicKey ed25519.PublicKey, target string, headers http.Header) (*Updater, error) {
	if client == nil || len(publicKey) != ed25519.PublicKeySize || target == "" {
		return nil, fmt.Errorf("updater requires HTTP client, Ed25519 public key and target")
	}
	return &Updater{client: client, publicKey: append(ed25519.PublicKey(nil), publicKey...), target: target, headers: headers.Clone()}, nil
}

func (u *Updater) Apply(ctx context.Context, manifestURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return err
	}
	copyHeaders(req.Header, u.headers)
	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("update manifest request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update manifest returned HTTP %d", resp.StatusCode)
	}
	var manifest UpdateManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&manifest); err != nil {
		return fmt.Errorf("decode update manifest: %w", err)
	}
	if manifest.BinaryURL == "" || manifest.Checksum == "" || manifest.Signature == "" {
		return fmt.Errorf("update manifest is incomplete")
	}
	if manifest.Version == "" {
		return fmt.Errorf("update manifest version is empty")
	}
	tmpFile, err := downloadBinary(ctx, u.client, manifest.BinaryURL, u.headers)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)
	if err := verifySignature(tmpFile, manifest.Checksum, manifest.Signature, u.publicKey); err != nil {
		return fmt.Errorf("update signature verification failed: %w", err)
	}
	backup, err := backupBinary(u.target)
	if err != nil {
		return fmt.Errorf("create update backup: %w", err)
	}
	if err := atomicReplace(tmpFile, u.target); err != nil {
		if backup != "" {
			_ = os.Remove(backup)
		}
		return fmt.Errorf("atomic binary replacement failed: %w", err)
	}
	u.mu.Lock()
	u.backup = backup
	u.mu.Unlock()
	slog.Info("Agent-Binary erfolgreich aktualisiert", "component", "updater", "version", manifest.Version)
	return nil
}

// Rollback restores the binary saved by the most recent successful Apply.
func (u *Updater) Rollback() error {
	u.mu.Lock()
	backup := u.backup
	u.mu.Unlock()
	if backup == "" {
		return fmt.Errorf("no update backup available")
	}
	if err := atomicReplace(backup, u.target); err != nil {
		return fmt.Errorf("rollback binary replacement failed: %w", err)
	}
	_ = os.Remove(backup)
	u.mu.Lock()
	u.backup = ""
	u.mu.Unlock()
	slog.Warn("Agent-Update zurückgerollt", "component", "updater", "target", u.target)
	return nil
}

func backupBinary(target string) (string, error) {
	input, err := os.Open(target)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer input.Close()
	backup, err := os.CreateTemp(filepath.Dir(target), "sentinel-backup-*")
	if err != nil {
		return "", err
	}
	name := backup.Name()
	cleanup := true
	defer func() {
		_ = backup.Close()
		if cleanup {
			_ = os.Remove(name)
		}
	}()
	if _, err := io.Copy(backup, input); err != nil {
		return "", err
	}
	if err := backup.Chmod(0755); err != nil {
		return "", err
	}
	if err := backup.Sync(); err != nil {
		return "", err
	}
	if err := backup.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return name, nil
}

func downloadBinary(ctx context.Context, client *http.Client, binaryURL string, headers http.Header) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, binaryURL, nil)
	if err != nil {
		return "", err
	}
	copyHeaders(req.Header, headers)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("binary download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("binary download returned HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "sentinel-update-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBinarySize+1)); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	info, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if info.Size() > maxBinarySize {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("downloaded binary exceeds %d bytes", maxBinarySize)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func copyHeaders(destination, source http.Header) {
	for key, values := range source {
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func verifySignature(filePath, expectedSHA256, encodedSignature string, publicKey ed25519.PublicKey) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return err
	}
	sum := digest.Sum(nil)
	if !strings.EqualFold(hex.EncodeToString(sum), expectedSHA256) {
		return fmt.Errorf("hash mismatch")
	}
	signature, err := hex.DecodeString(encodedSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid Ed25519 signature encoding")
	}
	if !ed25519.Verify(publicKey, sum, signature) {
		return fmt.Errorf("invalid Ed25519 signature")
	}
	return nil
}

func verifyChecksum(filePath, expectedSHA256 string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), expectedSHA256) {
		return fmt.Errorf("hash mismatch")
	}
	return nil
}

func atomicReplace(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	tmpDst, err := os.CreateTemp(filepath.Dir(dst), "sentinel-update-bin-*")
	if err != nil {
		_ = input.Close()
		return err
	}
	tmpName := tmpDst.Name()
	cleanup := true
	defer func() {
		_ = input.Close()
		_ = tmpDst.Close()
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmpDst, input); err != nil {
		return err
	}
	if err := tmpDst.Chmod(0755); err != nil {
		return err
	}
	if err := tmpDst.Sync(); err != nil {
		return err
	}
	if err := tmpDst.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	cleanup = false
	directory, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil && runtime.GOOS != "windows" {
		return syncErr
	}
	return closeErr
}

// RestartService asks systemd to start the newly installed binary.
func RestartService(ctx context.Context, serviceName string) error {
	if serviceName == "" {
		return fmt.Errorf("service name is empty")
	}
	command := exec.CommandContext(ctx, "systemctl", "restart", serviceName)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd restart failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
