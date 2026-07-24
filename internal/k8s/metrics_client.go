package k8s

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
	metricsclientset "k8s.io/metrics/pkg/client/clientset/versioned"
)

type MetricsClient struct {
	clientset     metricsclientset.Interface
	mu            sync.RWMutex
	available     bool
	lastCheck     time.Time
	checkInterval time.Duration
}

func NewMetricsClient() (*MetricsClient, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := metricsclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create metrics clientset: %w", err)
	}

	return &MetricsClient{
		clientset:     clientset,
		checkInterval: 5 * time.Minute,
	}, nil
}

func (c *MetricsClient) GetPodMetrics(ctx context.Context, namespace, name string) (*metricsv1beta1.PodMetrics, error) {
	avail, err := c.checkAvailable(ctx)
	if !avail {
		return nil, err
	}

	return c.clientset.MetricsV1beta1().PodMetricses(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *MetricsClient) IsAvailable(ctx context.Context) bool {
	avail, _ := c.checkAvailable(ctx)
	return avail
}

func (c *MetricsClient) checkAvailable(ctx context.Context) (bool, error) {
	c.mu.RLock()
	if time.Since(c.lastCheck) < c.checkInterval {
		avail := c.available
		c.mu.RUnlock()
		if !avail {
			return false, fmt.Errorf("metrics API not available (cached)")
		}
		return true, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.lastCheck) < c.checkInterval {
		return c.available, nil
	}

	c.lastCheck = time.Now()

	discoveryClient, ok := c.clientset.Discovery().(*discovery.DiscoveryClient)
	if !ok {
		c.available = false
		return false, fmt.Errorf("unexpected discovery client type")
	}

	apiGroupList, apiErr := discoveryClient.ServerGroups()
	if apiErr != nil {
		c.available = false
		return false, apiErr
	}

	for _, group := range apiGroupList.Groups {
		if group.Name == "metrics.k8s.io" {
			c.available = true
			return true, nil
		}
	}

	c.available = false
	return false, fmt.Errorf("metrics.k8s.io API group not found")
}

type MetricsSnapshot struct {
	CPUMillicores int64
	MemoryBytes   int64
}

func (c *MetricsClient) GetPodMetricsSnapshot(ctx context.Context, namespace, name string) (*MetricsSnapshot, error) {
	podMetrics, err := c.GetPodMetrics(ctx, namespace, name)
	if err != nil {
		return nil, err
	}

	if len(podMetrics.Containers) == 0 {
		return &MetricsSnapshot{}, nil
	}

	container := podMetrics.Containers[0]
	cpu := container.Usage.Cpu().MilliValue()
	memory, _ := container.Usage.Memory().AsInt64()

	return &MetricsSnapshot{
		CPUMillicores: cpu,
		MemoryBytes:   memory,
	}, nil
}
