// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package manifest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kraftkit.sh/archive"
	"kraftkit.sh/pack"
	"kraftkit.sh/unikraft"
	"kraftkit.sh/unikraft/app"
)

type TarballProvider struct {
	typ   unikraft.ComponentType
	name  string
	path  string
	mopts *ManifestOptions
}

func NewTarballProvider(ctx context.Context, path string, opts ...ManifestOption) (Provider, error) {
	if ok, err := archive.IsTarGz(path); !ok {
		return nil, fmt.Errorf("'%s' is not a tarball: %w", path, err)
	}

	// Determine the type preemptively
	n := strings.TrimSuffix(path, ".tar.gz")
	n = filepath.Base(n)
	t, n, _, err := unikraft.GuessTypeNameVersion(n)
	if err != nil || t == unikraft.ComponentTypeUnknown {
		for _, f := range app.DefaultFileNames {
			if f, err := os.Stat(filepath.Join(path, f)); err == nil && f.Size() > 0 {
				t = unikraft.ComponentTypeApp
				break
			}
		}
	}

	if t == unikraft.ComponentTypeUnknown {
		return nil, fmt.Errorf("unknown type for tarball: %s", path)
	}

	return &TarballProvider{
		typ:   t,
		name:  n,
		path:  path,
		mopts: NewManifestOptions(opts...),
	}, nil
}

func (provider TarballProvider) Manifests() ([]*Manifest, error) {
	return []*Manifest{
		{
			Type:     provider.typ,
			Name:     provider.name,
			Provider: provider,
			Origin:   provider.path,
			Channels: []ManifestChannel{
				{
					Name:     provider.mopts.defaultChannelName,
					Default:  true,
					Resource: provider.path,
				},
			},
		},
	}, nil
}

func (provider TarballProvider) pull(manifest *Manifest, opts ...pack.PullOption) error {
	popts, err := pack.NewPullOptions(opts...)
	if err != nil {
		return err
	}

	if len(popts.Workdir()) == 0 {
		return fmt.Errorf("cannot pull without without working directory")
	}

	// The directory provider only has one channel, exploit this knowledge
	if len(manifest.Channels) != 1 {
		return fmt.Errorf("cannot determine channel for directory provider")
	}

	local, err := unikraft.PlaceComponent(
		popts.Workdir(),
		manifest.Type,
		manifest.Name,
	)
	if err != nil {
		return fmt.Errorf("could not place component package: %s", err)
	}

	if err := archive.UntarGz(provider.path, local, archive.StripIfSingleTopLevelDir()); err != nil {
		return fmt.Errorf("could not untar: %s: %w", provider.path, err)
	}

	return nil
}

func (provider TarballProvider) PullChannel(ctx context.Context, manifest *Manifest, _ *ManifestChannel, opts ...pack.PullOption) error {
	return provider.pull(manifest, opts...)
}

func (provider TarballProvider) PullVersion(ctx context.Context, manifest *Manifest, _ *ManifestVersion, opts ...pack.PullOption) error {
	return provider.pull(manifest, opts...)
}

func (provider TarballProvider) DeleteManifest(context.Context) error {
	return nil
}

func (provider TarballProvider) String() string {
	return "tarball"
}

func (provider TarballProvider) MarshalJSON() ([]byte, error) {
	return []byte(`"tarball"`), nil
}
