// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackage(t *testing.T) {
	// This test ensures the package can be imported and used
	require.NotNil(t, NewHostnameService)
}
