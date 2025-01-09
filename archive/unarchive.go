// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Unarchive takes an input src file and determines (based on its extension)
func Unarchive(src, dst string, opts ...UnarchiveOption) error {
	switch true {
	case strings.HasSuffix(src, ".tar.gz"):
		return UntarGz(src, dst, opts...)
	}

	return fmt.Errorf("unrecognized extension: %s", filepath.Base(src))
}

// UntarGz unarchives a tarball which has been gzip compressed
func UntarGz(src, dst string, opts ...UnarchiveOption) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("could not open file: %v", err)
	}

	defer f.Close()

	gzipReader, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("could not open gzip reader: %v", err)
	}

	return Untar(gzipReader, dst, opts...)
}

// IsTarGz checks if a file is a valid tarball which has been gzip compressed.
func IsTarGz(filepath string) (bool, error) {
	// Open the file
	file, err := os.Open(filepath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Read the first few bytes to check gzip magic numbers
	buf := make([]byte, 2)
	if _, err := file.Read(buf); err != nil {
		return false, err
	}
	if !bytes.Equal(buf, []byte{0x1f, 0x8b}) { // Gzip magic numbers
		return false, nil
	}

	// Reset file pointer and create a gzip reader
	if _, err := file.Seek(0, 0); err != nil {
		return false, err
	}

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return false, nil // Not a valid gzip
	}
	defer gzr.Close()

	// Check if the gzip contains a tar archive
	buf = make([]byte, 512)
	if _, err := gzr.Read(buf); err != nil {
		return false, nil // Unable to read gzip contents
	}

	// TAR files typically start with a valid TAR header (file name, etc.)
	return bytes.HasPrefix(buf[257:], []byte("ustar")), nil
}

// Untar unarchives a tarball which has been gzip compressed
func Untar(src io.Reader, dst string, opts ...UnarchiveOption) error {
	uc := &UnarchiveOptions{}
	for _, opt := range opts {
		if err := opt(uc); err != nil {
			return err
		}
	}

	tr := tar.NewReader(src)

	if uc.stripIfOnlyDir {
		// Duplicate src so that we can reset it.
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, src); err != nil {
			return fmt.Errorf("could not copy reader: %v", err)
		}

		// Reset the buffer on exit
		defer buf.Reset()

		// Set the tarball readers by using the previously copied buffer.
		tr = tar.NewReader(bytes.NewReader(buf.Bytes()))
		tr2 := tar.NewReader(bytes.NewReader(buf.Bytes()))

		// Map to track top-level directory entries
		topLevelDirs := make(map[string]struct{})

		for {
			header, err := tr2.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to read tar header: %w", err)
			}

			// Split path components to identify the top-level directory
			components := strings.SplitN(header.Name, "/", 2)
			if len(components) > 0 && components[0] != "pax_global_header" {
				topLevelDirs[components[0]] = struct{}{}
			}

			// If more than one top-level directory is detected, exit
			if len(topLevelDirs) > 1 {
				break
			}
		}

		if len(topLevelDirs) == 1 {
			uc.stripComponents = 1
		}
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		var path string
		if uc.stripComponents > 0 {
			parts := strings.Split(header.Name, string(filepath.Separator))
			path = strings.Join(parts[uc.stripComponents:], string(filepath.Separator))
			path = filepath.Join(dst, path)
		} else {
			path = filepath.Join(dst, header.Name)
		}

		info := header.FileInfo()

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, info.Mode()); err != nil {
				return fmt.Errorf("could not create directory: %v", err)
			}

		case tar.TypeReg:
			// Create parent path if it does not exist
			if err := os.MkdirAll(filepath.Dir(path), info.Mode()); err != nil {
				return fmt.Errorf("could not create directory: %v", err)
			}

			newFile, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
			if err != nil {
				return fmt.Errorf("could not create file: %v", err)
			}

			if _, err := io.Copy(newFile, tr); err != nil {
				newFile.Close()
				return fmt.Errorf("could not copy file: %v", err)
			}

			newFile.Close()

			// TODO: Are there any other files we should consider?
			// default:
			// 	return fmt.Errorf("unknown type: %s in %s", string(header.Typeflag), path)
		}

		// Change access time and modification time if possible (error ignored)
		_ = os.Chtimes(path, header.AccessTime, header.ModTime)
	}

	return nil
}
