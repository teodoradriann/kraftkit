// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package manifest

import (
	"context"

	"kraftkit.sh/config"
)

// ManifestManagerOption represents a specific configuration that can be used
// for the Manifest Package Manager.
type ManifestManagerOption func(context.Context, *manifestManager) error

// Set the default set of source manifests to initialize the manager with.
// Not setting anything will result in defaults.
func WithManagerManifests(manifests ...string) ManifestManagerOption {
	return func(ctx context.Context, m *manifestManager) error {
		m.manifests = manifests
		return nil
	}
}

// Set the local directory where the manifests are stored.
func WithManagerLocalManifestDir(dir string) ManifestManagerOption {
	return func(ctx context.Context, m *manifestManager) error {
		m.localManifestDir = dir
		return nil
	}
}

// Set the default set of auths to initialize the manager with.
func WithManagerAuths(auths map[string]config.AuthConfig) ManifestManagerOption {
	return func(ctx context.Context, m *manifestManager) error {
		m.auths = auths
		return nil
	}
}

// Sets the default channel name to use when multiple channels are specified.
func WithManagerDefaultChannelName(name string) ManifestManagerOption {
	return func(ctx context.Context, m *manifestManager) error {
		m.defaultChannelName = name
		return nil
	}
}
