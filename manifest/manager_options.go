// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package manifest

import (
	"context"
)

// ManifestManagerOption represents a specific configuration that can be used
// for the Manifest Package Manager.
type ManifestManagerOption func(context.Context, *manifestManager) error

// Set the default set of source manifests to initialize the manager with.
// Not setting anything will result in defaults.
func WithManifests(manifests ...string) ManifestManagerOption {
	return func(ctx context.Context, m *manifestManager) error {
		m.manifests = manifests
		return nil
	}
}

// Set the local directory where the manifests are stored.
func WithLocalManifestDir(dir string) ManifestManagerOption {
	return func(ctx context.Context, m *manifestManager) error {
		m.localManifestDir = dir
		return nil
	}
}
