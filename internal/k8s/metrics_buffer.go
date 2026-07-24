package k8s

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"
)

type MetricPoint struct {
	Timestamp   time.Time `json:"timestamp"`
	CPUMillicores int64   `json:"cpu_mc"`
	MemoryBytes   int64   `json:"memory_bytes"`
}

type podBuffer struct {
	mu        sync.RWMutex
	points    []MetricPoint
	container string
	lastAccess time.Time
}

type MetricsBuffer struct {
	mu            sync.RWMutex
	pods          map[string]*podBuffer
	client        *MetricsClient
	interval      time.Duration
	maxAge        time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewMetricsBuffer(client *MetricsClient, interval, maxAge time.Duration) *MetricsBuffer {
	return &MetricsBuffer{
		pods:     make(map[string]*podBuffer),
		client:   client,
		interval: interval,
		maxAge:   maxAge,
	}
}

func (b *MetricsBuffer) Run(ctx context.Context) {
	b.ctx, b.cancel = context.WithCancel(ctx)

	ticker := time.NewTicker(b.interval)
	cleanupTicker := time.NewTicker(5 * time.Minute)

	go func() {
		defer ticker.Stop()
		defer cleanupTicker.Stop()

		for {
			select {
			case <-b.ctx.Done():
				return
			case <-ticker.C:
				b.poll()
			case <-cleanupTicker.C:
				b.cleanup()
			}
		}
	}()
}

func (b *MetricsBuffer) Stop() {
	if b.cancel != nil {
		b.cancel()
	}
}

func (b *MetricsBuffer) GetMetrics(namespace, name string, window time.Duration) ([]MetricPoint, string) {
	key := namespace + "/" + name

	b.mu.RLock()
	pb, exists := b.pods[key]
	b.mu.RUnlock()

	if !exists {
		return nil, ""
	}

	pb.mu.RLock()
	defer pb.mu.RUnlock()

	pb.lastAccess = time.Now()

	cutoff := time.Now().Add(-window)

	start := sort.Search(len(pb.points), func(i int) bool {
		return !pb.points[i].Timestamp.Before(cutoff)
	})

	raw := pb.points[start:]

	points := downsample(raw, window)

	return points, pb.container
}

func (b *MetricsBuffer) poll() {
	b.mu.RLock()
	keys := make([]string, 0, len(b.pods))
	for k := range b.pods {
		keys = append(keys, k)
	}
	b.mu.RUnlock()

	for _, key := range keys {
		parts := splitKey(key)
		if parts[0] == "" {
			continue
		}

		snapshot, err := b.client.GetPodMetricsSnapshot(b.ctx, parts[0], parts[1])
		if err != nil {
			log.Printf("metrics buffer: failed to get pod metrics for %s: %v", key, err)
			continue
		}

		b.mu.RLock()
		pb, exists := b.pods[key]
		b.mu.RUnlock()

		if !exists {
			continue
		}

		pb.mu.Lock()
		pb.points = append(pb.points, MetricPoint{
			Timestamp:     time.Now(),
			CPUMillicores: snapshot.CPUMillicores,
			MemoryBytes:   snapshot.MemoryBytes,
		})
		pb.mu.Unlock()
	}
}

func (b *MetricsBuffer) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-b.maxAge)
	accessCutoff := time.Now().Add(-10 * time.Minute)

	for key, pb := range b.pods {
		pb.mu.Lock()
		if pb.lastAccess.Before(accessCutoff) {
			pb.mu.Unlock()
			delete(b.pods, key)
			continue
		}

		idx := sort.Search(len(pb.points), func(i int) bool {
			return !pb.points[i].Timestamp.Before(cutoff)
		})
		pb.points = pb.points[idx:]
		pb.mu.Unlock()
	}
}

func (b *MetricsBuffer) Client() *MetricsClient {
	return b.client
}

func (b *MetricsBuffer) EnsurePod(ctx context.Context, namespace, name string, container string) {
	key := namespace + "/" + name

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.pods[key]; exists {
		return
	}

	b.pods[key] = &podBuffer{
		container:  container,
		lastAccess:  time.Now(),
	}
}

func downsample(points []MetricPoint, window time.Duration) []MetricPoint {
	if len(points) == 0 {
		return points
	}

	var bucketDuration time.Duration
	switch {
	case window <= 15*time.Minute:
		return points
	case window <= 1*time.Hour:
		return points
	case window <= 3*time.Hour:
		bucketDuration = time.Minute
	case window <= 6*time.Hour:
		bucketDuration = 2 * time.Minute
	default:
		bucketDuration = 5 * time.Minute
	}

	if bucketDuration == 0 {
		return points
	}

	var result []MetricPoint
	var currentBucket *time.Time
	var cpuSum, memSum int64
	var count int

	addBucket := func() {
		if count == 0 {
			return
		}
		result = append(result, MetricPoint{
			Timestamp:     *currentBucket,
			CPUMillicores: cpuSum / int64(count),
			MemoryBytes:   memSum / int64(count),
		})
	}

	for _, p := range points {
		bucket := p.Timestamp.Truncate(bucketDuration)

		if currentBucket == nil || !bucket.Equal(*currentBucket) {
			addBucket()
			currentBucket = &bucket
			cpuSum = 0
			memSum = 0
			count = 0
		}

		cpuSum += p.CPUMillicores
		memSum += p.MemoryBytes
		count++
	}

	addBucket()

	return result
}

func splitKey(key string) [2]string {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return [2]string{key[:i], key[i+1:]}
		}
	}
	return [2]string{}
}
