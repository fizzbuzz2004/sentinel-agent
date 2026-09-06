package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type ClientConfig struct {
	TenantID          string
	AgentID           string
	AuthToken         string
	CertFile          string
	KeyFile           string
	CAFile            string
	AllowInsecureHTTP bool
	Timeout           time.Duration
	Retry             RetryPolicy
	HTTPClient        *http.Client
}

type RetryPolicy struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Sleep     func(context.Context, time.Duration) error
	Random    func(int64) int64
}

type Client struct {
	httpClient *http.Client
	retry      RetryPolicy
}

func (c *Client) HTTPClient() *http.Client { return c.httpClient }

var gzipWriterPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}
var byteBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func NewClient(config ClientConfig) (*Client, error) {
	if config.TenantID == "" || config.AgentID == "" || config.AuthToken == "" {
		return nil, errors.New("tenant ID, agent ID and auth token are required")
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}
	if config.Retry.Attempts <= 0 {
		config.Retry.Attempts = 4
	}
	if config.Retry.BaseDelay <= 0 {
		config.Retry.BaseDelay = 250 * time.Millisecond
	}
	if config.Retry.MaxDelay <= 0 {
		config.Retry.MaxDelay = 30 * time.Second
	}
	if config.Retry.Sleep == nil {
		config.Retry.Sleep = sleepContext
	}
	if config.Retry.Random == nil {
		config.Retry.Random = func(max int64) int64 {
			if max <= 0 {
				return 0
			}
			var raw [8]byte
			if _, err := rand.Read(raw[:]); err != nil {
				return mathrand.Int63n(max)
			}
			value := binary.LittleEndian.Uint64(raw[:])
			return int64(value % uint64(max))
		}
	}
	client := config.HTTPClient
	if client == nil {
		transport, err := newTransport(config)
		if err != nil {
			return nil, err
		}
		client = &http.Client{Transport: transport, Timeout: config.Timeout}
	}
	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}
	client.Transport = authTransport{base: client.Transport, tenantID: config.TenantID, agentID: config.AgentID, authToken: config.AuthToken}
	return &Client{httpClient: client, retry: config.Retry}, nil
}

func newTransport(config ClientConfig) (*http.Transport, error) {
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if config.AllowInsecureHTTP {
		return transport, nil
	}
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load agent mTLS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse agent certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("agent certificate is expired or not yet valid")
	}
	caPEM, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read hub CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid hub CA certificate")
	}
	transport.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	return transport, nil
}

type authTransport struct {
	base                         http.RoundTripper
	tenantID, agentID, authToken string
}

func (t authTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("X-Tenant-ID", t.tenantID)
	clone.Header.Set("X-Agent-ID", t.agentID)
	clone.Header.Set("Authorization", "Bearer "+t.authToken)
	return t.base.RoundTrip(clone)
}

func (c *Client) Do(ctx context.Context, method, endpoint string, body io.Reader, headers http.Header) (*http.Response, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = io.ReadAll(body)
		if err != nil {
			return nil, err
		}
	}
	var response *http.Response
	var lastErr error
	for attempt := 0; attempt < c.retry.Attempts; attempt++ {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
		if err != nil {
			return nil, err
		}
		for key, values := range headers {
			for _, value := range values {
				request.Header.Add(key, value)
			}
		}
		response, err = c.httpClient.Do(request)
		if err == nil && response.StatusCode < http.StatusInternalServerError && response.StatusCode != http.StatusTooManyRequests {
			return response, nil
		}
		if response != nil {
			response.Body.Close()
			lastErr = fmt.Errorf("hub returned HTTP %d", response.StatusCode)
		} else {
			lastErr = err
		}
		if attempt+1 == c.retry.Attempts {
			break
		}
		delay := c.retryDelay(attempt)
		if err := c.retry.Sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) retryDelay(attempt int) time.Duration {
	shift := attempt
	if shift > 30 {
		shift = 30
	}
	cap := c.retry.BaseDelay * time.Duration(uint64(1)<<shift)
	if cap > c.retry.MaxDelay || cap < 0 {
		cap = c.retry.MaxDelay
	}
	return time.Duration(c.retry.Random(cap.Nanoseconds() + 1))
}

func (c *Client) Enroll(ctx context.Context, endpoint, enrollToken, nodeID, agentID string, customerID int) (EnrollmentResponse, error) {
	payload, err := json.Marshal(map[string]any{"enroll_token": enrollToken, "node_id": nodeID, "agent_id": agentID, "customer_id": customerID})
	if err != nil {
		return EnrollmentResponse{}, err
	}
	response, err := c.Do(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/api/v1/agent/enroll", bytes.NewReader(payload), http.Header{"Content-Type": []string{"application/json"}})
	if err != nil {
		return EnrollmentResponse{}, err
	}
	defer response.Body.Close()
	var enrollment EnrollmentResponse
	if err := json.NewDecoder(response.Body).Decode(&enrollment); err != nil {
		return EnrollmentResponse{}, err
	}
	return enrollment, nil
}

func (c *Client) SendCompressed(ctx context.Context, endpoint string, compressed []byte) error {
	response, err := c.Do(ctx, http.MethodPost, endpoint, bytes.NewReader(compressed), http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func CompressJSON(value any) ([]byte, error) {
	buffer := byteBufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer byteBufferPool.Put(buffer)
	writer := gzipWriterPool.Get().(*gzip.Writer)
	writer.Reset(buffer)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		writer.Reset(io.Discard)
		gzipWriterPool.Put(writer)
		return nil, err
	}
	if err := writer.Close(); err != nil {
		gzipWriterPool.Put(writer)
		return nil, err
	}
	compressed := append([]byte(nil), buffer.Bytes()...)
	writer.Reset(io.Discard)
	gzipWriterPool.Put(writer)
	return compressed, nil
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
