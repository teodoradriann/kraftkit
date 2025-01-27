package unikraft

import (
	"debug/elf"
	"fmt"
	"os"

	"kraftkit.sh/internal/set"
)

var errNotUnikraftUnikernel = fmt.Errorf("provided file is not a Unikraft unikernel")

// isArm64Kernel is a utility method that determines whether the provided
// input file is of the supported ARM format. This does not guarantee that
// the file is a Unikraft unikernel, as it can't access the ELF sections.
// We can assume that it is though, and fail at a later stage.
func isArm64Kernel(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}

	// Read the first 64 bytes of the file
	buf := make([]byte, 64)
	n, err := f.Read(buf)
	if err != nil {
		return false, err
	}
	if n < 64 {
		return false, errNotUnikraftUnikernel
	}

	defer f.Close()

	// Check for MS-DOS MZ header (ARM) which is always present
	msdosHeader := buf[2:4]
	armMsdosHeader := []byte{0x4d, 0x5a}
	for i, b := range armMsdosHeader {
		if msdosHeader[i] != b {
			return false, errNotUnikraftUnikernel
		}
	}

	// Check for magic bytes 0x644d5241 (ARM)
	// These are 4 bytes placed at offset 56 in the header
	magic := buf[56:60]
	armMagic := []byte{0x41, 0x52, 0x4d, 0x64}
	for i, b := range armMagic {
		if magic[i] != b {
			return false, errNotUnikraftUnikernel
		}
	}

	return true, nil
}

// / isX86_64Kernel is a utility method that determines whether the provided
// input file is of the supported x86 format. If sections are found then this
// guarantees that the file is a Unikraft unikernel.
func isX86_64Kernel(path string) (bool, error) {
	// Sanity check whether the provided file is an ELF kernel with
	// Unikraft-centric properties.  This check might not always work, especially
	// if the version changes and the sections change name.
	//
	// TODO(nderjung): This check should be replaced with a more stable mechanism
	// that detects whether a bootflag is set. See[0].
	// [0]: https://github.com/unikraft/unikraft/pull/
	fe, err := elf.Open(path)
	if err != nil {
		return false, err
	}

	defer fe.Close()

	knownUnikraftSections := set.NewStringSet(
		".uk_inittab",
		".uk_ctortab",
		".uk_thread_inittab",
	)
	for _, symbol := range fe.Sections {
		if knownUnikraftSections.ContainsExactly(symbol.Name) {
			return true, nil
		}
	}

	return false, errNotUnikraftUnikernel
}

// IsFileUnikraftUnikernel is a utility method that determines whether the
// provided input file is a Unikraft unikernel.  The file is checked with a
// number of known facts about the kernel image built with Unikraft.
func IsFileUnikraftUnikernel(path string) (bool, error) {
	fs, err := os.Stat(path)
	if err != nil {
		return false, err
	} else if fs.IsDir() {
		return false, fmt.Errorf("first positional argument is a directory: %v", path)
	}

	if ok, _ := isX86_64Kernel(path); ok {
		return true, nil
	} else if ok, _ := isArm64Kernel(path); ok {
		return true, nil
	}

	return false, errNotUnikraftUnikernel
}
