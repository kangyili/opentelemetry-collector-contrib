// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sclusterreceiver/internal/metadata"
)

// metricValue finds a single data point value in m by metric name and data point attributes.
// Returns (value, found). Only handles Int and Double data points.
func metricValue(t *testing.T, m pmetric.Metrics, metricName string, dpAttrs map[string]string) (float64, bool) {
	t.Helper()
	for i := 0; i < m.ResourceMetrics().Len(); i++ {
		for j := 0; j < m.ResourceMetrics().At(i).ScopeMetrics().Len(); j++ {
			metrics := m.ResourceMetrics().At(i).ScopeMetrics().At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				metric := metrics.At(k)
				if metric.Name() != metricName {
					continue
				}
				var dps pmetric.NumberDataPointSlice
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					dps = metric.Gauge().DataPoints()
				case pmetric.MetricTypeSum:
					dps = metric.Sum().DataPoints()
				default:
					continue
				}
				for l := 0; l < dps.Len(); l++ {
					dp := dps.At(l)
					match := true
					for attrKey, attrVal := range dpAttrs {
						v, ok := dp.Attributes().Get(attrKey)
						if !ok || v.Str() != attrVal {
							match = false
							break
						}
					}
					if match {
						switch dp.ValueType() {
						case pmetric.NumberDataPointValueTypeInt:
							return float64(dp.IntValue()), true
						case pmetric.NumberDataPointValueTypeDouble:
							return dp.DoubleValue(), true
						}
					}
				}
			}
		}
	}
	return 0, false
}

func TestRecordSpecMetrics(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-namespace",
			UID:       types.UID("test-pod-uid"),
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "docker/test-image:v1.0",
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("2"),
							corev1.ResourceMemory: resource.MustParse("512Mi"),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("256Mi"),
						},
					},
				},
			},
		},
	}

	ts := pcommon.Timestamp(time.Now().UnixNano())

	t.Run("running container", func(t *testing.T) {
		pod := pod.DeepCopy()
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:         "test-container",
				Image:        "docker/test-image:v1.0",
				ContainerID:  "docker://abc123",
				Ready:        true,
				RestartCount: 2,
				State: corev1.ContainerState{
					Running: &corev1.ContainerStateRunning{},
				},
			},
		}

		mb := metadata.NewMetricsBuilder(metadata.DefaultMetricsBuilderConfig(), receivertest.NewNopSettings(metadata.Type))
		RecordSpecMetrics(zap.NewNop(), mb, pod.Spec.Containers[0], pod, ts)
		m := mb.Emit()

		v, ok := metricValue(t, m, "k8s.container.cpu_request", nil)
		require.True(t, ok)
		assert.InDelta(t, 0.5, v, 0.001)

		v, ok = metricValue(t, m, "k8s.container.cpu_limit", nil)
		require.True(t, ok)
		assert.InDelta(t, 2.0, v, 0.001)

		v, ok = metricValue(t, m, "k8s.container.memory_request", nil)
		require.True(t, ok)
		assert.Equal(t, float64(256*1024*1024), v)

		v, ok = metricValue(t, m, "k8s.container.memory_limit", nil)
		require.True(t, ok)
		assert.Equal(t, float64(512*1024*1024), v)

		v, ok = metricValue(t, m, "k8s.container.restarts", nil)
		require.True(t, ok)
		assert.Equal(t, float64(2), v)

		v, ok = metricValue(t, m, "k8s.container.ready", nil)
		require.True(t, ok)
		assert.Equal(t, float64(1), v)
	})

	t.Run("terminated container records restarts and ready=0", func(t *testing.T) {
		pod := pod.DeepCopy()
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:         "test-container",
				Image:        "docker/test-image:v1.0",
				ContainerID:  "docker://def456",
				Ready:        false,
				RestartCount: 5,
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						Reason:   "OOMKilled",
						ExitCode: 137,
					},
				},
				LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						Reason: "OOMKilled",
					},
				},
			},
		}

		mbc := metadata.DefaultMetricsBuilderConfig()
		mbc.Metrics.K8sContainerStatusState.Enabled = true
		mbc.Metrics.K8sContainerStatusReason.Enabled = true
		mb := metadata.NewMetricsBuilder(mbc, receivertest.NewNopSettings(metadata.Type))
		RecordSpecMetrics(zap.NewNop(), mb, pod.Spec.Containers[0], pod, ts)
		m := mb.Emit()

		v, ok := metricValue(t, m, "k8s.container.restarts", nil)
		require.True(t, ok)
		assert.Equal(t, float64(5), v)

		v, ok = metricValue(t, m, "k8s.container.ready", nil)
		require.True(t, ok)
		assert.Equal(t, float64(0), v)

		// Terminated state: terminated=1, others=0.
		v, ok = metricValue(t, m, "k8s.container.status.state", map[string]string{"k8s.container.status.state": "terminated"})
		require.True(t, ok)
		assert.Equal(t, float64(1), v)

		v, ok = metricValue(t, m, "k8s.container.status.state", map[string]string{"k8s.container.status.state": "running"})
		require.True(t, ok)
		assert.Equal(t, float64(0), v)

		v, ok = metricValue(t, m, "k8s.container.status.state", map[string]string{"k8s.container.status.state": "waiting"})
		require.True(t, ok)
		assert.Equal(t, float64(0), v)

		// OOMKilled reason=1, others=0.
		v, ok = metricValue(t, m, "k8s.container.status.reason", map[string]string{"k8s.container.status.reason": "OOMKilled"})
		require.True(t, ok)
		assert.Equal(t, float64(1), v)

		v, ok = metricValue(t, m, "k8s.container.status.reason", map[string]string{"k8s.container.status.reason": "CrashLoopBackOff"})
		require.True(t, ok)
		assert.Equal(t, float64(0), v)
	})

	t.Run("waiting container", func(t *testing.T) {
		pod := pod.DeepCopy()
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:         "test-container",
				Image:        "docker/test-image:v1.0",
				ContainerID:  "",
				Ready:        false,
				RestartCount: 3,
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason: "CrashLoopBackOff",
					},
				},
			},
		}

		mbc := metadata.DefaultMetricsBuilderConfig()
		mbc.Metrics.K8sContainerStatusState.Enabled = true
		mbc.Metrics.K8sContainerStatusReason.Enabled = true
		mb := metadata.NewMetricsBuilder(mbc, receivertest.NewNopSettings(metadata.Type))
		RecordSpecMetrics(zap.NewNop(), mb, pod.Spec.Containers[0], pod, ts)
		m := mb.Emit()

		// Waiting state: waiting=1, others=0.
		v, ok := metricValue(t, m, "k8s.container.status.state", map[string]string{"k8s.container.status.state": "waiting"})
		require.True(t, ok)
		assert.Equal(t, float64(1), v)

		v, ok = metricValue(t, m, "k8s.container.status.state", map[string]string{"k8s.container.status.state": "running"})
		require.True(t, ok)
		assert.Equal(t, float64(0), v)

		v, ok = metricValue(t, m, "k8s.container.status.state", map[string]string{"k8s.container.status.state": "terminated"})
		require.True(t, ok)
		assert.Equal(t, float64(0), v)

		// CrashLoopBackOff reason=1, others=0.
		v, ok = metricValue(t, m, "k8s.container.status.reason", map[string]string{"k8s.container.status.reason": "CrashLoopBackOff"})
		require.True(t, ok)
		assert.Equal(t, float64(1), v)

		v, ok = metricValue(t, m, "k8s.container.status.reason", map[string]string{"k8s.container.status.reason": "OOMKilled"})
		require.True(t, ok)
		assert.Equal(t, float64(0), v)
	})

	t.Run("no matching container status", func(t *testing.T) {
		// Pod has no ContainerStatuses, so cs is nil inside RecordSpecMetrics.
		// This covers the nil guard added around docker.ParseImageName.
		pod := pod.DeepCopy()

		mb := metadata.NewMetricsBuilder(metadata.DefaultMetricsBuilderConfig(), receivertest.NewNopSettings(metadata.Type))
		RecordSpecMetrics(zap.NewNop(), mb, pod.Spec.Containers[0], pod, ts)
		m := mb.Emit()

		// Resource-level metrics from the spec are still recorded.
		v, ok := metricValue(t, m, "k8s.container.cpu_request", nil)
		require.True(t, ok)
		assert.InDelta(t, 0.5, v, 0.001)

		v, ok = metricValue(t, m, "k8s.container.cpu_limit", nil)
		require.True(t, ok)
		assert.InDelta(t, 2.0, v, 0.001)

		// Per-status metrics (restarts, ready) are not emitted when cs is nil.
		_, ok = metricValue(t, m, "k8s.container.restarts", nil)
		assert.False(t, ok)

		_, ok = metricValue(t, m, "k8s.container.ready", nil)
		assert.False(t, ok)
	})
}

func TestGetMetadata(t *testing.T) {
	refTime := v1.Now()
	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-namespace",
			UID:       types.UID("test-pod-uid"),
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}

	tests := []struct {
		name               string
		containerState     corev1.ContainerState
		expectedStatus     string
		expectedReason     string
		expectedStartedAt  string
		containerName      string
		containerID        string
		containerImage     string
		containerImageName string
		containerImageTag  string
		podName            string
		podUID             string
		nodeName           string
		namespaceName      string
	}{
		{
			name: "Running container",
			containerState: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{
					StartedAt: refTime,
				},
			},
			expectedStatus:     containerStatusRunning,
			expectedStartedAt:  refTime.Format(time.RFC3339),
			containerName:      "my-test-container1",
			containerID:        "f37ee861-f093-4cea-aa26-f39fff8b0998",
			containerImage:     "docker/someimage1:v1.0",
			containerImageName: "docker/someimage1",
			containerImageTag:  "v1.0",
			podName:            pod.Name,
			podUID:             string(pod.UID),
			namespaceName:      "test-namespace",
			nodeName:           "test-node",
		},
		{
			name: "Terminated container",
			containerState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ContainerID: "container-id",
					Reason:      "Completed",
					StartedAt:   refTime,
					FinishedAt:  refTime,
					ExitCode:    0,
				},
			},
			expectedStatus:     containerStatusTerminated,
			expectedReason:     "Completed",
			expectedStartedAt:  refTime.Format(time.RFC3339),
			containerName:      "my-test-container2",
			containerID:        "f37ee861-f093-4cea-aa26-f39fff8b0997",
			containerImage:     "docker/someimage2:v1.1",
			containerImageName: "docker/someimage2",
			containerImageTag:  "v1.1",
			podName:            pod.Name,
			podUID:             string(pod.UID),
			namespaceName:      "test-namespace",
			nodeName:           "test-node",
		},
		{
			name: "Waiting container",
			containerState: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason: "CrashLoopBackOff",
				},
			},
			expectedStatus:     containerStatusWaiting,
			expectedReason:     "CrashLoopBackOff",
			containerName:      "my-test-container3",
			containerID:        "f37ee861-f093-4cea-aa26-f39fff8b0996",
			containerImage:     "docker/someimage3:latest",
			containerImageName: "docker/someimage3",
			containerImageTag:  "latest",
			podName:            pod.Name,
			podUID:             string(pod.UID),
			namespaceName:      "test-namespace",
			nodeName:           "test-node",
		},
	}
	logger := zap.NewNop()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := corev1.ContainerStatus{
				State:       tt.containerState,
				Name:        tt.containerName,
				ContainerID: tt.containerID,
				Image:       tt.containerImage,
			}
			md := GetMetadata(pod, cs, logger)

			require.NotNil(t, md)
			assert.Equal(t, tt.expectedStatus, md.Metadata[containerKeyStatus])
			if tt.expectedReason != "" {
				assert.Equal(t, tt.expectedReason, md.Metadata[containerKeyStatusReason])
			}
			if tt.containerState.Running != nil || tt.containerState.Terminated != nil {
				assert.Contains(t, md.Metadata, containerCreationTimestamp)
				assert.Equal(t, tt.expectedStartedAt, md.Metadata[containerCreationTimestamp])
			}
			assert.Equal(t, tt.containerName, md.Metadata[containerName])
			assert.Equal(t, tt.containerImageName, md.Metadata[containerImageName])
			assert.Equal(t, tt.containerImageTag, md.Metadata[containerImageTag])
			assert.Equal(t, tt.podName, md.Metadata["k8s.pod.name"])
			assert.Equal(t, tt.podUID, md.Metadata["k8s.pod.uid"])
			assert.Equal(t, tt.namespaceName, md.Metadata["k8s.namespace.name"])
			assert.Equal(t, tt.nodeName, md.Metadata["k8s.node.name"])
		})
	}
}
