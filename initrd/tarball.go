// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.

package initrd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"

	"kraftkit.sh/archive"
	"kraftkit.sh/cpio"
	"kraftkit.sh/log"
)

type tarball struct {
	opts InitrdOptions
	path string
}

func NewFromTarball(_ context.Context, tb string, opts ...InitrdOption) (Initrd, error) {
	rootfs := tarball{
		opts: InitrdOptions{},
		path: tb,
	}

	for _, opt := range opts {
		if err := opt(&rootfs.opts); err != nil {
			return nil, err
		}
	}

	if !path.IsAbs(tb) {
		rootfs.path = filepath.Join(rootfs.opts.workdir, tb)
	}

	if tarOk, _ := archive.IsTarGz(rootfs.path); !tarOk {
		if tarGzOk, _ := archive.IsTar(rootfs.path); !tarGzOk {
			return nil, fmt.Errorf("supplied path is not a tarball: %s", rootfs.path)
		}
	}

	return &rootfs, nil
}

// Name implements Initrd.
func (initrd *tarball) Name() string {
	return "tarball"
}

// Build implements Initrd.
func (initrd *tarball) Build(ctx context.Context) (string, error) {
	if initrd.opts.output == "" {
		fi, err := os.CreateTemp("", "")
		if err != nil {
			return "", err
		}

		initrd.opts.output = fi.Name()
	}

	if err := os.MkdirAll(filepath.Dir(initrd.opts.output), 0o755); err != nil {
		return "", fmt.Errorf("could not create output directory: %w", err)
	}

	cpioFile, err := os.OpenFile(initrd.opts.output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("could not open initramfs file: %w", err)
	}

	defer cpioFile.Close()

	cpioWriter := cpio.NewWriter(cpioFile)

	defer cpioWriter.Close()

	tarArchive, err := os.Open(initrd.path)
	if err != nil {
		return "", fmt.Errorf("could not open tarball: %v", err)
	}

	// We create a Closer which is necessary to seek to zero in the tarball after
	// we've counted the number of links for the inode count.
	var close func() error

	var tarReader *tar.Reader
	if gzr, err := gzip.NewReader(tarArchive); err == nil {
		tarReader = tar.NewReader(gzr)
		close = gzr.Close
	} else {
		tarReader = tar.NewReader(tarArchive)
		close = func() error { return nil }
	}

	type inodeCount struct {
		Count int
		Inode int32
	}
	fileCount := map[string]inodeCount{}

	// Pass once to count links
	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return "", fmt.Errorf("could not read tar header: %w", err)
		}

		if tarHeader.Typeflag == tar.TypeLink {
			if _, ok := fileCount[tarHeader.Linkname]; !ok {
				fileCount[tarHeader.Linkname] = inodeCount{
					Count: 1,
					Inode: rand.Int32(),
				}
			} else {
				fileCount[tarHeader.Linkname] = inodeCount{
					Count: fileCount[tarHeader.Linkname].Count + 1,
					Inode: fileCount[tarHeader.Linkname].Inode,
				}
			}
		} else if tarHeader.Typeflag == tar.TypeReg {
			if _, ok := fileCount[tarHeader.Name]; !ok {
				fileCount[tarHeader.Name] = inodeCount{
					Count: 1,
					Inode: rand.Int32(),
				}
			} else {
				fileCount[tarHeader.Name] = inodeCount{
					Count: fileCount[tarHeader.Name].Count + 1,
					Inode: fileCount[tarHeader.Linkname].Inode,
				}
			}
		}
	}

	// Close the tarball and re-open it to read it again.
	if err := close(); err != nil {
		return "", err
	}

	_, err = tarArchive.Seek(0, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("could not seek to start of tarball: %w", err)
	}

	if gzr, err := gzip.NewReader(tarArchive); err == nil {
		tarReader = tar.NewReader(gzr)
	} else {
		tarReader = tar.NewReader(tarArchive)
	}

	for {
		tarHeader, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return "", fmt.Errorf("could not read tar header: %w", err)
		}

		internal := fmt.Sprintf("./%s", filepath.Clean(tarHeader.Name))

		if internal == "./." {
			continue
		}

		cpioHeader := &cpio.Header{
			Name:    internal,
			Mode:    cpio.FileMode(tarHeader.FileInfo().Mode().Perm()),
			ModTime: tarHeader.FileInfo().ModTime(),
			Size:    tarHeader.FileInfo().Size(),
		}

		switch tarHeader.Typeflag {
		case tar.TypeBlock:
			log.G(ctx).
				WithField("file", tarHeader.Name).
				Warn("ignoring block devices")
			continue

		case tar.TypeChar:
			log.G(ctx).
				WithField("file", tarHeader.Name).
				Warn("ignoring char devices")
			continue

		case tar.TypeFifo:
			log.G(ctx).
				WithField("file", tarHeader.Name).
				Warn("ignoring fifo files")
			continue

		case tar.TypeSymlink:
			log.G(ctx).
				WithField("src", tarHeader.Name).
				WithField("link", tarHeader.Linkname).
				Trace("symlinking")

			cpioHeader.Mode |= cpio.TypeSymlink
			cpioHeader.Linkname = tarHeader.Linkname
			cpioHeader.Size = int64(len(tarHeader.Linkname))

			if err := cpioWriter.WriteHeader(cpioHeader); err != nil {
				return "", fmt.Errorf("could not write CPIO header: %w", err)
			}

			if _, err := cpioWriter.Write([]byte(tarHeader.Linkname)); err != nil {
				return "", fmt.Errorf("could not write CPIO data for %s: %w", internal, err)
			}

		case tar.TypeLink:
			log.G(ctx).
				WithField("src", tarHeader.Name).
				WithField("link", tarHeader.Linkname).
				Trace("hardlinking")

			cpioHeader.Mode |= cpio.TypeReg
			cpioHeader.Linkname = tarHeader.Linkname
			cpioHeader.Size = 0
			if _, ok := fileCount[tarHeader.Linkname]; ok {
				cpioHeader.Links = fileCount[tarHeader.Linkname].Count
				cpioHeader.Inode = int64(fileCount[tarHeader.Linkname].Inode)
			}
			if err := cpioWriter.WriteHeader(cpioHeader); err != nil {
				return "", fmt.Errorf("could not write CPIO header: %w", err)
			}

		case tar.TypeReg:
			log.G(ctx).
				WithField("src", tarHeader.Name).
				WithField("dst", internal).
				Trace("copying")

			cpioHeader.Mode |= cpio.TypeReg
			cpioHeader.Linkname = tarHeader.Linkname
			cpioHeader.Size = tarHeader.FileInfo().Size()
			if _, ok := fileCount[tarHeader.Name]; ok {
				cpioHeader.Links = fileCount[tarHeader.Name].Count
				cpioHeader.Inode = int64(fileCount[tarHeader.Name].Inode)
			}

			if err := cpioWriter.WriteHeader(cpioHeader); err != nil {
				return "", fmt.Errorf("could not write CPIO header: %w", err)
			}

			data, err := io.ReadAll(tarReader)
			if err != nil {
				return "", fmt.Errorf("could not read file: %w", err)
			}

			if _, err := cpioWriter.Write(data); err != nil {
				return "", fmt.Errorf("could not write CPIO data for %s: %w", internal, err)
			}

		case tar.TypeDir:
			log.G(ctx).
				WithField("dst", internal).
				Trace("mkdir")

			cpioHeader.Mode |= cpio.TypeDir

			if err := cpioWriter.WriteHeader(cpioHeader); err != nil {
				return "", fmt.Errorf("could not write CPIO header: %w", err)
			}

		default:
			log.G(ctx).
				WithField("file", tarHeader.Name).
				WithField("type", tarHeader.Typeflag).
				Warn("unsupported file type")
		}
	}

	return initrd.opts.output, nil
}

// Env implements Initrd.
func (initrd *tarball) Env() []string {
	return nil
}

// Args implements Initrd.
func (initrd *tarball) Args() []string {
	return nil
}
