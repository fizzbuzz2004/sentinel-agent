//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows/svc"
)

type service struct {
	binary  string
	mu      sync.Mutex
	command *exec.Cmd
}

func (s *service) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := loadAgentEnvironment(); err != nil {
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}
	s.mu.Lock()
	s.command = exec.CommandContext(ctx, s.binary)
	s.mu.Unlock()
	if err := s.command.Start(); err != nil {
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			return false, 0
		}
	}
	return false, 0
}

func loadAgentEnvironment() error {
	data, err := os.ReadFile(filepath.Join(os.Getenv("ProgramData"), "SentinelAgent", "agent.env.json"))
	if err != nil {
		return err
	}
	values := map[string]string{}
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	for key, value := range values {
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	_ = svc.Run("SentinelAgent", &service{binary: `C:\Program Files\SentinelAgent\sentinel-agent.exe`})
}
