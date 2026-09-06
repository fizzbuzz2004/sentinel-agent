package config

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type RuntimeConfig struct {
	CollectorInterval time.Duration
	LogLevel          slog.Level
	Update            *UpdateSignal
}

type UpdateSignal struct {
	Version     string `json:"version"`
	ManifestURL string `json:"manifest_url"`
}

type configResponse struct {
	CollectorIntervalSeconds int           `json:"collector_interval_seconds"`
	LogLevel                 string        `json:"log_level"`
	Update                   *UpdateSignal `json:"update"`
}

type Store struct {
	current atomic.Pointer[RuntimeConfig]
}

func NewStore(initial RuntimeConfig) *Store {
	store := &Store{}
	store.current.Store(&initial)
	return store
}

func (s *Store) Load() RuntimeConfig {
	config := s.current.Load()
	if config == nil {
		return RuntimeConfig{CollectorInterval: 30 * time.Second, LogLevel: slog.LevelInfo}
	}
	return *config
}

func (s *Store) Update(next RuntimeConfig) error {
	if next.CollectorInterval <= 0 {
		return fmt.Errorf("collector interval must be greater than zero")
	}
	s.current.Store(&next)
	return nil
}

type Poller struct {
	clientProvider func() (*http.Client, error)
	endpoint       string
	store          *Store
	level          *slog.LevelVar
	interval       time.Duration
	headers        http.Header
	updateHandler  func(context.Context, UpdateSignal) error
}

func NewPoller(endpoint string, interval time.Duration, store *Store, level *slog.LevelVar, clientProvider func() (*http.Client, error)) (*Poller, error) {
	return NewPollerWithOptions(endpoint, interval, store, level, nil, nil, clientProvider)
}

func NewPollerWithOptions(endpoint string, interval time.Duration, store *Store, level *slog.LevelVar, headers http.Header, updateHandler func(context.Context, UpdateSignal) error, clientProvider func() (*http.Client, error)) (*Poller, error) {
	if endpoint == "" || store == nil || level == nil || clientProvider == nil {
		return nil, fmt.Errorf("config poller requires endpoint, store, level and client provider")
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &Poller{endpoint: endpoint, interval: interval, store: store, level: level, headers: headers.Clone(), updateHandler: updateHandler, clientProvider: clientProvider}, nil
}

func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.poll(ctx); err != nil {
				slog.Warn("Runtime-Konfiguration konnte nicht aktualisiert werden", "component", "config", "error", err)
			}
		}
	}
}

func (p *Poller) poll(ctx context.Context) error {
	var resp *http.Response
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		client, err := p.clientProvider()
		if err == nil {
			var req *http.Request
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint, nil)
			if err == nil {
				for key, values := range p.headers {
					for _, value := range values {
						req.Header.Add(key, value)
					}
				}
				resp, err = client.Do(req)
			}
		}
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			lastErr = fmt.Errorf("config server returned HTTP %d", resp.StatusCode)
			_ = resp.Body.Close()
			resp = nil
		} else {
			lastErr = err
		}
		if attempt == 3 || !isTransient(lastErr) {
			return lastErr
		}
		if err := waitWithJitter(ctx, attempt); err != nil {
			return err
		}
	}
	if resp == nil {
		return lastErr
	}
	defer resp.Body.Close()

	var payload configResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("decode runtime config: %w", err)
	}
	next := p.store.Load()
	if payload.CollectorIntervalSeconds > 0 {
		next.CollectorInterval = time.Duration(payload.CollectorIntervalSeconds) * time.Second
	}
	if payload.LogLevel != "" {
		level, err := parseLevel(payload.LogLevel)
		if err != nil {
			return err
		}
		next.LogLevel = level
	}
	next.Update = payload.Update
	if err := p.store.Update(next); err != nil {
		return err
	}
	p.level.Set(next.LogLevel)
	if next.Update != nil && p.updateHandler != nil {
		if err := p.updateHandler(ctx, *next.Update); err != nil {
			return fmt.Errorf("apply agent update: %w", err)
		}
	}
	slog.Info("Runtime-Konfiguration aktualisiert", "component", "config", "collector_interval", next.CollectorInterval, "log_level", next.LogLevel.String())
	return nil
}

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "HTTP 5") || strings.Contains(message, "HTTP 429") || !strings.Contains(message, "HTTP ")
}

func waitWithJitter(ctx context.Context, attempt int) error {
	cap := 250 * time.Millisecond * time.Duration(uint64(1)<<attempt)
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	delay := time.Duration(binary.LittleEndian.Uint64(raw[:]) % uint64(cap))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func parseLevel(value string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(value)); err != nil {
		return 0, fmt.Errorf("invalid log level %q: %w", value, err)
	}
	return level, nil
}
