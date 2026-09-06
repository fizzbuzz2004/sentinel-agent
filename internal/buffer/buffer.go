package buffer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type MetricPayload struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "metric" oder "hardening"
	Data      any       `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

type DiskBuffer struct {
	mu           sync.Mutex
	flushMu      sync.Mutex
	filePath     string
	maxSize      int
	maxFileBytes int64
	aesKey       []byte
	queue        []MetricPayload
	diskOnly     bool
	closed       bool
}

const defaultMaxFileBytes int64 = 10 * 1024 * 1024

var gzipWriterPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}
var gzipBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func NewDiskBuffer(storagePath string, maxSize int, masterKey []byte) (*DiskBuffer, error) {
	return NewDiskBufferWithLimits(storagePath, maxSize, defaultMaxFileBytes, masterKey)
}

// NewDiskBufferWithLimits creates an AES-GCM disk-backed FIFO with item and byte limits.
func NewDiskBufferWithLimits(storagePath string, maxSize int, maxFileBytes int64, masterKey []byte) (*DiskBuffer, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("AES-256 Key muss exakt 32 Byte lang sein")
	}
	if maxSize <= 0 {
		return nil, errors.New("buffer max size must be greater than zero")
	}
	if maxFileBytes <= 0 {
		return nil, errors.New("buffer max file size must be greater than zero")
	}
	if err := os.MkdirAll(filepath.Dir(storagePath), 0700); err != nil {
		return nil, fmt.Errorf("buffer dir creation failed: %w", err)
	}

	buf := &DiskBuffer{
		filePath:     storagePath,
		maxSize:      maxSize,
		maxFileBytes: maxFileBytes,
		aesKey:       append([]byte(nil), masterKey...),
		queue:        make([]MetricPayload, 0),
	}

	if err := buf.loadFromDisk(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to restore encrypted buffer: %w", err)
	}

	return buf, nil
}

func (b *DiskBuffer) Enqueue(eventType string, data any) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("buffer is closed")
	}
	if err := b.ensureLoadedLocked(); err != nil {
		return err
	}
	previousQueue := append([]MetricPayload(nil), b.queue...)

	item := MetricPayload{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Type:      eventType,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	if len(b.queue) >= b.maxSize {
		b.queue = b.queue[1:]
		slog.Warn("Ringbuffer full: dropped oldest record", "max_size", b.maxSize)
	}

	b.queue = append(b.queue, item)
	if err := b.persistToDiskLocked(); err != nil {
		b.queue = previousQueue
		return err
	}
	return nil
}

// Sync durably persists the current in-memory queue without contacting the hub.
func (b *DiskBuffer) Sync() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.diskOnly {
		return nil
	}
	return b.persistToDiskLocked()
}

// Close durably persists the queue and prevents writes after shutdown.
func (b *DiskBuffer) Close() error {
	b.flushMu.Lock()
	defer b.flushMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	if !b.diskOnly {
		if err := b.persistToDiskLocked(); err != nil {
			return err
		}
	}
	b.closed = true
	return nil
}

// ReleaseMemoryToDisk keeps the durable queue on disk and releases its in-memory copy.
func (b *DiskBuffer) ReleaseMemoryToDisk() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("buffer is closed")
	}
	if b.diskOnly {
		return nil
	}
	if err := b.persistToDiskLocked(); err != nil {
		return err
	}
	b.queue = nil
	b.diskOnly = true
	return nil
}

// FlushCompress (Ihr genialer Code bleibt erhalten!)
func (b *DiskBuffer) FlushCompress(ctx context.Context, sendFunc func(ctx context.Context, compressedGzip []byte) error) error {
	b.flushMu.Lock()
	defer b.flushMu.Unlock()

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("buffer is closed")
	}
	if err := b.ensureLoadedLocked(); err != nil {
		b.mu.Unlock()
		return err
	}
	if len(b.queue) == 0 {
		b.mu.Unlock()
		return nil
	}

	itemsToSend := make([]MetricPayload, len(b.queue))
	copy(itemsToSend, b.queue)
	b.mu.Unlock()

	rawJSON, err := json.Marshal(itemsToSend)
	if err != nil {
		return fmt.Errorf("buffer serialization failed: %w", err)
	}

	gzipBuffer := gzipBufferPool.Get().(*bytes.Buffer)
	gzipBuffer.Reset()
	defer gzipBufferPool.Put(gzipBuffer)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(gzipBuffer)
	if _, err := gzipWriter.Write(rawJSON); err != nil {
		_ = gzipWriter.Close()
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
		return fmt.Errorf("gzip compression failed: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
		return fmt.Errorf("gzip writer close failed: %w", err)
	}
	compressed := append([]byte(nil), gzipBuffer.Bytes()...)
	gzipWriter.Reset(io.Discard)
	gzipWriterPool.Put(gzipWriter)

	if err := sendFunc(ctx, compressed); err != nil {
		return fmt.Errorf("flush callback failed: %w", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	previousQueue := b.queue
	b.queue = b.queue[len(itemsToSend):]
	if err := b.persistToDiskLocked(); err != nil {
		b.queue = previousQueue
		return err
	}
	return nil
}

func (b *DiskBuffer) persistToDiskLocked() error {
	hadItems := len(b.queue) > 0
	block, err := aes.NewCipher(b.aesKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	candidate := b.queue
	for len(candidate) > 0 {
		rawJSON, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		if int64(len(rawJSON)+gcm.NonceSize()+gcm.Overhead()) <= b.maxFileBytes {
			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return err
			}
			ciphertext := gcm.Seal(nonce, nonce, rawJSON, nil)
			if err := b.writeAtomically(ciphertext); err != nil {
				return err
			}
			b.queue = candidate
			return nil
		}

		slog.Warn("Disk-Buffer-Limit erreicht; ältestes Ereignis verworfen", "component", "buffer", "max_file_bytes", b.maxFileBytes)
		candidate = candidate[1:]
	}

	if err := os.Remove(b.filePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if hadItems {
		return fmt.Errorf("buffer item exceeds configured file limit of %d bytes", b.maxFileBytes)
	}
	return nil
}

func (b *DiskBuffer) writeAtomically(ciphertext []byte) error {
	directory := filepath.Dir(b.filePath)
	tmp, err := os.CreateTemp(directory, filepath.Base(b.filePath)+".tmp-")
	if err != nil {
		return err
	}
	tmpFile := tmp.Name()
	defer os.Remove(tmpFile)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	for written := 0; written < len(ciphertext); {
		n, writeErr := tmp.Write(ciphertext[written:])
		written += n
		if writeErr != nil {
			_ = tmp.Close()
			return writeErr
		}
		if n == 0 {
			_ = tmp.Close()
			return io.ErrShortWrite
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpFile, b.filePath); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil && runtime.GOOS != "windows" {
		return syncErr
	}
	return closeErr
}

// NEU: Entschlüsseltes Laden von der Festplatte
func (b *DiskBuffer) loadFromDisk() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loadFromDiskLocked()
}

func (b *DiskBuffer) ensureLoadedLocked() error {
	if !b.diskOnly {
		return nil
	}
	if err := b.loadFromDiskLocked(); err != nil {
		return err
	}
	b.diskOnly = false
	return nil
}

func (b *DiskBuffer) loadFromDiskLocked() error {
	info, err := os.Stat(b.filePath)
	if err != nil {
		return err
	}
	if info.Size() > b.maxFileBytes {
		return fmt.Errorf("buffer file exceeds configured limit: %d > %d bytes", info.Size(), b.maxFileBytes)
	}
	ciphertext, err := os.ReadFile(b.filePath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(b.aesKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext zu kurz")
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	rawJSON, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return errors.New("entschlüsselung fehlgeschlagen - Integritätsverletzung oder falscher Key")
	}

	if err := json.Unmarshal(rawJSON, &b.queue); err != nil {
		return err
	}
	if len(b.queue) > b.maxSize {
		b.queue = b.queue[len(b.queue)-b.maxSize:]
	}
	return nil
}
