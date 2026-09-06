package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifySignatureAcceptsValidBinary(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "agent")
	payload := []byte("signed-agent-binary")
	if err := os.WriteFile(path, payload, 0700); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	digest := sha256.Sum256(payload)
	signature := hex.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	if err := verifySignature(path, hex.EncodeToString(digest[:]), signature, publicKey); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifySignatureRejectsTamperedBinary(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "agent")
	original := []byte("signed-agent-binary")
	if err := os.WriteFile(path, original, 0700); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	digest := sha256.Sum256(original)
	signature := hex.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	if err := os.WriteFile(path, []byte("tampered-binary"), 0700); err != nil {
		t.Fatalf("tamper binary: %v", err)
	}
	if err := verifySignature(path, hex.EncodeToString(digest[:]), signature, publicKey); err == nil {
		t.Fatal("tampered binary passed signature verification")
	}
}

func TestAtomicReplaceSynchronizesAndPreservesNewBinary(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "download")
	target := filepath.Join(directory, "agent")
	if err := os.WriteFile(source, []byte("new-agent"), 0600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.WriteFile(target, []byte("old-agent"), 0700); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := atomicReplace(source, target); err != nil {
		t.Fatalf("atomic replace: %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(content) != "new-agent" {
		t.Fatalf("unexpected target content: %q", content)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source should remain available for caller cleanup: %v", err)
	}
}

func TestApplyCreatesBackupAndRollsBack(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "agent")
	if err := os.WriteFile(target, []byte("old-agent"), 0700); err != nil {
		t.Fatal(err)
	}
	newBinary := []byte("new-agent")
	digest := sha256.Sum256(newBinary)
	manifest := UpdateManifest{Version: "2.0.0", BinaryURL: "/binary", Checksum: hex.EncodeToString(digest[:]), Signature: hex.EncodeToString(ed25519.Sign(privateKey, digest[:]))}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json" {
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		if r.URL.Path == "/binary" {
			_, _ = w.Write(newBinary)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	manifest.BinaryURL = server.URL + "/binary"
	manager, err := New(http.DefaultClient, publicKey, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), server.URL+"/manifest.json"); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(target)
	if string(content) != "new-agent" {
		t.Fatalf("updated binary = %q", content)
	}
	if err := manager.Rollback(); err != nil {
		t.Fatal(err)
	}
	content, _ = os.ReadFile(target)
	if string(content) != "old-agent" {
		t.Fatalf("rolled back binary = %q", content)
	}
}
