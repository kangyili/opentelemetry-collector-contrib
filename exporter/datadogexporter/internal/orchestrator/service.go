// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package orchestrator // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/datadogexporter/internal/orchestrator"

import (
	"context"

	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameinterface"
	"github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/attributes/source"
)

// HostnameProvider defines the interface for getting hostname information
type HostnameProvider interface {
	Source(ctx context.Context) (source.Source, error)
}

type service struct {
	provider source.Provider
}

var _ hostnameinterface.Component = (*service)(nil)
var _ HostnameProvider = (*service)(nil)

// Get returns the hostname.
func (hs *service) Get(ctx context.Context) (string, error) {
	src, err := hs.provider.Source(ctx)
	if err != nil {
		return "", err
	}

	hostname := ""
	if src.Kind == source.HostnameKind {
		hostname = src.Identifier
	}

	return hostname, nil
}

// GetSafe returns the hostname, or 'unknown host' if anything goes wrong.
func (hs *service) GetSafe(ctx context.Context) string {
	name, err := hs.Get(ctx)
	if err != nil {
		return "unknown host"
	}
	return name
}

// GetWithProvider returns the hostname for the Agent and the provider that was use to retrieve it.
func (hs *service) GetWithProvider(ctx context.Context) (hostnameinterface.Data, error) {
	name, err := hs.Get(ctx)
	if err != nil {
		return hostnameinterface.Data{}, err
	}

	return hostnameinterface.Data{
		Hostname: name,
		Provider: "",
	}, nil
}

// Source implements HostnameProvider interface
func (hs *service) Source(ctx context.Context) (source.Source, error) {
	return hs.provider.Source(ctx)
}

// NewHostnameService creates a new instance of the component hostname
func NewHostnameService(provider source.Provider) hostnameinterface.Component {
	return &service{
		provider: provider,
	}
}

// NewHostnameProvider creates a new hostname provider
func NewHostnameProvider(provider source.Provider) HostnameProvider {
	return &service{
		provider: provider,
	}
}
