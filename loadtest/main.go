package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"sentinel-agent/internal/agent"
	"sentinel-agent/internal/hub"
)

func main() {
	agents := flag.Int("agents", 512, "number of concurrent agent workers")
	flag.Parse()
	if *agents < 1 {
		panic("agents must be greater than zero")
	}

	backend := hub.NewServer(hub.Config{AuthToken: "load-auth", EnrollmentToken: "load-enroll"})
	server := httptest.NewServer(backend.Handler())
	defer server.Close()

	started := time.Now()
	var failures atomic.Int32
	var waitGroup sync.WaitGroup
	waitGroup.Add(*agents)
	for worker := 0; worker < *agents; worker++ {
		go func(worker int) {
			defer waitGroup.Done()
			client, err := agent.NewClient(agent.ClientConfig{
				TenantID: "load-tenant", AgentID: fmt.Sprintf("load-agent-%04d", worker), AuthToken: "load-auth",
				AllowInsecureHTTP: true, Timeout: 10 * time.Second, Retry: agent.RetryPolicy{Attempts: 8, BaseDelay: 5 * time.Millisecond, MaxDelay: 250 * time.Millisecond},
			})
			if err != nil {
				failures.Add(1)
				return
			}
			if _, err := client.Enroll(context.Background(), server.URL, "load-enroll", fmt.Sprintf("load-node-%04d", worker), fmt.Sprintf("load-agent-%04d", worker), worker); err != nil {
				failures.Add(1)
				return
			}
			events := []hub.MetricEvent{
				metricEvent(fmt.Sprintf("metric-%04d", worker), "system_metric", fmt.Sprintf("load-node-%04d", worker)),
				metricEvent(fmt.Sprintf("fim-%04d", worker), "fim_alert", fmt.Sprintf("load-node-%04d", worker)),
			}
			payload, err := agent.CompressJSON(events)
			if err != nil || client.SendCompressed(context.Background(), server.URL+"/api/v1/metrics", payload) != nil {
				failures.Add(1)
			}
		}(worker)
	}
	waitGroup.Wait()
	fmt.Printf("agents=%d events=%d failures=%d duration=%s\n", *agents, backend.MetricsCount(), failures.Load(), time.Since(started).Round(time.Millisecond))
	if failures.Load() != 0 || backend.MetricsCount() != *agents*2 {
		panic("load test failed")
	}
}

func metricEvent(id, eventType, nodeID string) hub.MetricEvent {
	data := map[string]any{"node_id": nodeID, "timestamp": time.Now().UTC()}
	if eventType == "fim_alert" {
		data["file_path"] = "/etc/sentinel/load-test"
		data["event"] = "MODIFIED"
	} else {
		data["cpu_usage_pct"] = 12.0
		data["ram_usage_pct"] = 24.0
		data["disk_usage_pct"] = 36.0
		data["status"] = "healthy"
	}
	payload, _ := json.Marshal(data)
	return hub.MetricEvent{ID: id, Type: eventType, Data: payload, Timestamp: time.Now().UTC()}
}
