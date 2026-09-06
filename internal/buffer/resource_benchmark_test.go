package buffer

import (
	"runtime"
	"testing"
)

func BenchmarkEncryptedDiskSpooling(b *testing.B) {
	buffer, err := NewDiskBuffer(b.TempDir()+"/benchmark.dat", 10000, []byte("01234567890123456789012345678901"))
	if err != nil {
		b.Fatal(err)
	}
	defer buffer.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := buffer.Enqueue("system_metric", map[string]any{"node_id": "benchmark-node", "cpu_usage_pct": float64(index % 100)}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	b.ReportMetric(float64(stats.HeapAlloc), "heap-bytes")
}
