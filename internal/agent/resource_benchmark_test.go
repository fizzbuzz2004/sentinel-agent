package agent

import (
	"runtime"
	"testing"
	"time"
)

func BenchmarkMetricsGenerationAndGZIPParallel(b *testing.B) {
	payload := make([]map[string]any, 32)
	for index := range payload {
		payload[index] = map[string]any{
			"id": index, "type": "system_metric",
			"data":      map[string]any{"node_id": "benchmark-node", "cpu_usage_pct": 42.5, "ram_usage_pct": 61.2, "disk_usage_pct": 70.1, "status": "healthy"},
			"timestamp": time.Now().UTC(),
		}
	}
	b.ReportAllocs()
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			compressed, err := CompressJSON(payload)
			if err != nil {
				b.Fatal(err)
			}
			if len(compressed) == 0 {
				b.Fatal("empty compressed payload")
			}
		}
	})
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	b.ReportMetric(float64(stats.HeapAlloc), "heap-bytes")
}
