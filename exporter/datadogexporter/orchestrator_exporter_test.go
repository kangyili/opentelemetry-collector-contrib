// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package datadogexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter"

import (
	"context"
	"testing"

	"github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/attributes/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter/exportertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter/internal/orchestrator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/datadog/config"
)

func TestNewOrchestratorExporter(t *testing.T) {
	cfg := &config.Config{
		API: config.APIConfig{
			Key:  "test-key",
			Site: "datadoghq.com",
		},
		Orchestrator: config.OrchestratorConfig{
			ClusterName: "test-cluster",
		},
	}

	params := exportertest.NewNopSettings(component.MustNewType("datadog"))

	// Create a mock source provider
	mockProvider := &mockSourceProvider{
		source: source.Source{
			Kind:       source.HostnameKind,
			Identifier: "test-hostname",
		},
	}

	hostnameProvider := orchestrator.NewHostnameProvider(mockProvider)
	exporter, err := newOrchestratorExporter(params, cfg, hostnameProvider)
	require.NoError(t, err)
	assert.NotNil(t, exporter)
}

// mockSourceProvider is a mock implementation of source.Provider for testing
type mockSourceProvider struct {
	source source.Source
	err    error
}

func (m *mockSourceProvider) Source(ctx context.Context) (source.Source, error) {
	if m.err != nil {
		return source.Source{}, m.err
	}
	return m.source, nil
}
