// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/datadog/config"

import "go.opentelemetry.io/collector/config/confignet"

// OrchestratorConfig defines orchestrator exporter specific configuration
type OrchestratorConfig struct {
	// TCPAddr.Endpoint is the host of the Datadog orchestrator intake server to send data to.
	// If unset, the value is obtained from the Site.
	confignet.TCPAddrConfig `mapstructure:",squash"`

	// UseCompression enables the orchestrator agent to compress data before sending them.
	UseCompression bool `mapstructure:"use_compression"`

	// CompressionLevel accepts values from 0 (no compression) to 9 (maximum compression but higher resource usage).
	// Only takes effect if UseCompression is set to true.
	CompressionLevel int `mapstructure:"compression_level"`

	// BatchWait represents the maximum time the orchestrator agent waits to fill each batch before sending.
	BatchWait int `mapstructure:"batch_wait"`

	// ClusterName is the name of the Kubernetes cluster to associate with the orchestrator data.
	ClusterName string `mapstructure:"cluster_name"`

	// ClusterChecksEnabled enables cluster checks for the orchestrator data.
	ClusterChecksEnabled bool `mapstructure:"cluster_checks_enabled"`

	// CollectEvents enables collection of Kubernetes events.
	CollectEvents bool `mapstructure:"collect_events"`

	// LeaderElection enables leader election for orchestrator data collection.
	LeaderElection bool `mapstructure:"leader_election"`

	// LeaderLeaseDuration is the duration of the leader lease.
	LeaderLeaseDuration int `mapstructure:"leader_lease_duration"`

	// LeaderRenewDeadline is the deadline for leader lease renewal.
	LeaderRenewDeadline int `mapstructure:"leader_renew_deadline"`

	// LeaderRetryPeriod is the retry period for leader election.
	LeaderRetryPeriod int `mapstructure:"leader_retry_period"`
}
