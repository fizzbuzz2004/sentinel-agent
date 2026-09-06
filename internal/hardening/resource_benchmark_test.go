package hardening

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
)

func BenchmarkParallelFIMTriggers(b *testing.B) {
	directory := b.TempDir()
	paths := make([]string, runtime.GOMAXPROCS(0)*2)
	for index := range paths {
		paths[index] = filepath.Join(directory, "critical-"+strconv.Itoa(index)+".conf")
		if err := os.WriteFile(paths[index], []byte("baseline"), 0600); err != nil {
			b.Fatal(err)
		}
	}
	scanner := NewFIMScanner(paths)
	scanner.BuildBaseline()
	b.ReportAllocs()
	b.ResetTimer()
	var lock sync.Mutex
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			lock.Lock()
			_ = os.WriteFile(paths[0], []byte("changed"), 0600)
			lock.Unlock()
			_ = scanner.CheckIntegrity("benchmark-node")
		}
	})
	b.StopTimer()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	b.ReportMetric(float64(stats.HeapAlloc), "heap-bytes")
}
