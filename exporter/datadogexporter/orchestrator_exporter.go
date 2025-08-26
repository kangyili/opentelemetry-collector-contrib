// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package datadogexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	agentmodel "github.com/DataDog/agent-payload/v5/process"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter/internal/orchestrator"
	datadogconfig "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/datadog/config"
)

const (
	// orchestratorSourceName specifies the Datadog source tag value to be added to orchestrator data sent from the Datadog exporter.
	orchestratorSourceName = "otlp_orchestrator_ingestion"
	// otelOrchestratorSource specifies a source to be added to all orchestrator data sent from the Datadog exporter.
	otelOrchestratorSource = "datadog_orchestrator_exporter"
)

// orchestratorExporter handles the export of Kubernetes resource manifests to DataDog's Orchestrator endpoint
type orchestratorExporter struct {
	logger     *zap.Logger
	config     *datadogconfig.Config
	httpClient *http.Client
	hostname   string
}

// newOrchestratorExporter creates a new orchestrator exporter
func newOrchestratorExporter(
	params exporter.Settings,
	cfg *datadogconfig.Config,
	hostProvider orchestrator.HostnameProvider,
) (*orchestratorExporter, error) {
	host, err := hostProvider.Source(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get host source: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &orchestratorExporter{
		logger:     params.Logger,
		config:     cfg,
		httpClient: httpClient,
		hostname:   host.Identifier,
	}, nil
}

// ConsumeLogs implements the consumer.ConsumeLogs interface
func (e *orchestratorExporter) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		resourceLogs := logs.ResourceLogs().At(i)
		resource := resourceLogs.Resource()

		for j := 0; j < resourceLogs.ScopeLogs().Len(); j++ {
			scopeLogs := resourceLogs.ScopeLogs().At(j)

			for k := 0; k < scopeLogs.LogRecords().Len(); k++ {
				logRecord := scopeLogs.LogRecords().At(k)

				// Convert Kubernetes resource manifest to orchestrator payload format
				manifestPayload, err := e.convertToCollectorManifest(logRecord, resource)
				if err != nil {
					e.logger.Error("Failed to convert to collector manifest", zap.Error(err))
					continue
				}

				// Send to DataDog Orchestrator endpoint
				if err := e.sendToOrchestratorEndpoint(ctx, manifestPayload); err != nil {
					e.logger.Error("Failed to send collector manifest", zap.Error(err))
					continue
				}
			}
		}
	}
	return nil
}

// convertToCollectorManifest converts a Kubernetes resource manifest to the agent-payload CollectorManifest format
func (e *orchestratorExporter) convertToCollectorManifest(logRecord plog.LogRecord, resource pcommon.Resource) (*agentmodel.CollectorManifest, error) {
	// Extract the Kubernetes resource data from the log record body
	var k8sResource map[string]interface{}
	if err := json.Unmarshal([]byte(logRecord.Body().AsString()), &k8sResource); err != nil {
		return nil, fmt.Errorf("failed to unmarshal k8s resource: %w", err)
	}

	// Convert the Kubernetes resource to JSON bytes for the manifest content
	content, err := json.Marshal(k8sResource)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal k8s resource content: %w", err)
	}

	// Extract resource type and version from the Kubernetes resource
	apiVersion, _ := k8sResource["apiVersion"].(string)
	kind, _ := k8sResource["kind"].(string)
	metadata, _ := k8sResource["metadata"].(map[string]interface{})
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)

	// Determine manifest type based on the Kubernetes resource kind
	manifestType := e.getManifestType(kind)

	// Build tags from resource and log record attributes
	tags := e.buildTags(resource, logRecord)

	// Create the manifest
	manifest := &agentmodel.Manifest{
		Type:            int32(manifestType),
		ResourceVersion: resourceVersion,
		Uid:             uid,
		Content:         content,
		ContentType:     "application/json",
		Version:         "v1",
		Tags:            tags,
		IsTerminated:    false,
		ApiVersion:      apiVersion,
		Kind:            kind,
	}

	// Create the collector manifest payload
	collectorManifest := &agentmodel.CollectorManifest{
		ClusterName: e.config.Orchestrator.ClusterName,
		ClusterId:   "12345689",
		HostName:    e.hostname,
		Manifests:   []*agentmodel.Manifest{manifest},
		Tags:        tags,
	}

	return collectorManifest, nil
}

// getManifestType maps Kubernetes resource kinds to agent-payload manifest types
func (e *orchestratorExporter) getManifestType(kind string) int {
	switch kind {
	case "Pod":
		return int(K8sPod)
	case "Deployment":
		return int(K8sDeployment)
	case "Service":
		return int(K8sService)
	case "Node":
		return int(K8sNode)
	case "Namespace":
		return int(K8sNamespace)
	case "ReplicaSet":
		return int(K8sReplicaSet)
	case "DaemonSet":
		return int(K8sDaemonSet)
	case "StatefulSet":
		return int(K8sStatefulSet)
	case "Job":
		return int(K8sJob)
	case "CronJob":
		return int(K8sCronJob)
	case "PersistentVolume":
		return int(K8sPersistentVolume)
	case "PersistentVolumeClaim":
		return int(K8sPersistentVolumeClaim)
	case "Ingress":
		return int(K8sIngress)
	case "NetworkPolicy":
		return int(K8sNetworkPolicy)
	case "StorageClass":
		return int(K8sStorageClass)
	case "LimitRange":
		return int(K8sLimitRange)
	case "PodDisruptionBudget":
		return int(K8sPodDisruptionBudget)
	default:
		// For unknown types, use the generic manifest type
		return int(K8sUnsetType)
	}
}

// buildTags extracts tags from resource and log record attributes
func (e *orchestratorExporter) buildTags(resource pcommon.Resource, logRecord plog.LogRecord) []string {
	tags := []string{
		fmt.Sprintf("source:%s", orchestratorSourceName),
		fmt.Sprintf("orchestrator:%s", otelOrchestratorSource),
	}

	// Add resource attributes as tags
	resource.Attributes().Range(func(key string, value pcommon.Value) bool {
		tags = append(tags, fmt.Sprintf("%s:%s", key, value.AsString()))
		return true
	})

	// Add log record attributes as tags
	logRecord.Attributes().Range(func(key string, value pcommon.Value) bool {
		tags = append(tags, fmt.Sprintf("%s:%s", key, value.AsString()))
		return true
	})

	return tags
}

// sendToOrchestratorEndpoint sends the collector manifest to DataDog's Orchestrator endpoint
func (e *orchestratorExporter) sendToOrchestratorEndpoint(ctx context.Context, payload *agentmodel.CollectorManifest) error {

	// Determine the endpoint
	endpoint := e.config.Orchestrator.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://orchestrator.%s", e.config.API.Site)
	}
	endpoint = endpoint + "/api/v2/orchmanif"

	encoded, err := agentmodel.EncodeMessage(agentmodel.Message{
		Header: agentmodel.MessageHeader{
			Version:  agentmodel.MessageV3,
			Encoding: agentmodel.MessageEncodingZstdPBxNoCgo,
			Type:     agentmodel.TypeCollectorManifest,
		}, Body: payload})
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("DD-API-KEY", string(e.config.API.Key))
	req.Header.Set("X-Dd-Hostname", e.hostname)
	req.Header.Set("X-DD-Agent-Timestamp", strconv.Itoa(int(time.Now().Unix())))
	req.Header.Set("X-Dd-Orchestrator-ClusterID", "12345689")
	req.Header.Set("DD-EVP-ORIGIN", "agent")
	req.Header.Set("DD-EVP-ORIGIN-VERSION", "1.0.0")

	// Send the request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("orchestrator endpoint:%s returned status: %d", endpoint, resp.StatusCode)
	}

	return nil
}

type NodeType int

const (
	// K8sUnsetType represents a Kubernetes unset type
	K8sUnsetType NodeType = 0
	// K8sPod represents a Kubernetes Pod
	K8sPod = 1
	// K8sReplicaSet represents a Kubernetes ReplicaSet
	K8sReplicaSet = 2
	// K8sService represents a Kubernetes Service
	K8sService = 3
	// K8sNode represents a Kubernetes Node
	K8sNode = 4
	// K8sCluster represents a Kubernetes Cluster
	K8sCluster = 5
	// K8sJob represents a Kubernetes Job
	K8sJob = 6
	// K8sCronJob represents a Kubernetes CronJob
	K8sCronJob = 7
	// K8sDaemonSet represents a Kubernetes DaemonSet
	K8sDaemonSet = 8
	// K8sStatefulSet represents a Kubernetes StatefulSet
	K8sStatefulSet = 9
	// K8sPersistentVolume represents a Kubernetes PersistentVolume
	K8sPersistentVolume = 10
	// K8sPersistentVolumeClaim represents a Kubernetes PersistentVolumeClaim
	K8sPersistentVolumeClaim = 11
	// K8sRole represents a Kubernetes Role
	K8sRole = 12
	// K8sRoleBinding represents a Kubernetes RoleBinding
	K8sRoleBinding = 13
	// K8sClusterRole represents a Kubernetes ClusterRole
	K8sClusterRole = 14
	// K8sClusterRoleBinding represents a Kubernetes ClusterRoleBinding
	K8sClusterRoleBinding = 15
	// K8sServiceAccount represents a Kubernetes ServiceAccount
	K8sServiceAccount = 16
	// K8sIngress represents a Kubernetes Ingress
	K8sIngress = 17
	// K8sDeployment represents a Kubernetes Deployment
	K8sDeployment = 18
	// K8sNamespace represents a Kubernetes Namespace
	K8sNamespace = 19
	// K8sCRD represents a Kubernetes CRD
	K8sCRD = 20
	// K8sCR represents a Kubernetes CR
	K8sCR = 21
	// K8sVerticalPodAutoscaler represents a Kubernetes VerticalPod Autoscaler
	K8sVerticalPodAutoscaler = 22
	// K8sHorizontalPodAutoscaler represents a Kubernetes Horizontal Pod Autoscaler
	K8sHorizontalPodAutoscaler = 23
	// K8sNetworkPolicy represents a Kubernetes NetworkPolicy
	K8sNetworkPolicy = 24
	// K8sLimitRange represents a Kubernetes LimitRange
	K8sLimitRange = 25
	// K8sStorageClass represents a Kubernetes StorageClass
	K8sStorageClass = 26
	// K8sPodDisruptionBudget represents a Kubernetes PodDisruptionBudget
	K8sPodDisruptionBudget = 27
	// K8sEndpointSlice represents a Kubernetes EndpointSlice
	K8sEndpointSlice = 28
	// ECSTask represents an ECS Task
	ECSTask = 150
)
