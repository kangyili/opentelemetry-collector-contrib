// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package orchestrator // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter/internal/orchestrator"

import (
	"context"
	"testing"

	"github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/attributes/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHostnameService(t *testing.T) {
	// Create a mock source provider
	mockProvider := &mockSourceProvider{
		source: source.Source{
			Kind:       source.HostnameKind,
			Identifier: "test-hostname",
		},
	}

	service := NewHostnameService(mockProvider)
	require.NotNil(t, service)

	// Test Get method
	hostname, err := service.Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-hostname", hostname)

	// Test GetSafe method
	safeHostname := service.GetSafe(context.Background())
	assert.Equal(t, "test-hostname", safeHostname)

	// Test GetWithProvider method
	data, err := service.GetWithProvider(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-hostname", data.Hostname)
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
