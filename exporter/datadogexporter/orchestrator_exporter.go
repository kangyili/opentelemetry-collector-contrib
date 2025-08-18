// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package datadogexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	agentmodel "github.com/DataDog/agent-payload/v5/process"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

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
		return int(agentmodel.TypeCollectorPod)
	case "Deployment":
		return int(agentmodel.TypeCollectorDeployment)
	case "Service":
		return int(agentmodel.TypeCollectorService)
	case "Node":
		return int(agentmodel.TypeCollectorNode)
	case "Namespace":
		return int(agentmodel.TypeCollectorNamespace)
	case "ReplicaSet":
		return int(agentmodel.TypeCollectorReplicaSet)
	case "DaemonSet":
		return int(agentmodel.TypeCollectorDaemonSet)
	case "StatefulSet":
		return int(agentmodel.TypeCollectorStatefulSet)
	case "Job":
		return int(agentmodel.TypeCollectorJob)
	case "CronJob":
		return int(agentmodel.TypeCollectorCronJob)
	case "PersistentVolume":
		return int(agentmodel.TypeCollectorPersistentVolume)
	case "PersistentVolumeClaim":
		return int(agentmodel.TypeCollectorPersistentVolumeClaim)
	case "ConfigMap":
		return int(agentmodel.TypeCollectorManifest)
	case "Secret":
		return int(agentmodel.TypeCollectorManifest)
	case "Ingress":
		return int(agentmodel.TypeCollectorIngress)
	case "NetworkPolicy":
		return int(agentmodel.TypeCollectorNetworkPolicy)
	case "StorageClass":
		return int(agentmodel.TypeCollectorStorageClass)
	case "LimitRange":
		return int(agentmodel.TypeCollectorLimitRange)
	case "PodDisruptionBudget":
		return int(agentmodel.TypeCollectorPodDisruptionBudget)
	default:
		// For unknown types, use the generic manifest type
		return int(agentmodel.TypeCollectorManifest)
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
	// Marshal the payload to protobuf
	protoData, err := payload.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal collector manifest: %w", err)
	}

	// Determine the endpoint
	endpoint := e.config.Orchestrator.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://orchestrator.%s", e.config.API.Site)
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(protoData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("DD-API-KEY", string(e.config.API.Key))
	req.Header.Set("DD-AGENT-HOSTNAME", e.hostname)

	// Send the request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("orchestrator endpoint returned status: %d", resp.StatusCode)
	}

	return nil
}
