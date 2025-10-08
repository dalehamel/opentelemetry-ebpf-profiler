// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// MemoryRecorder wraps a RemoteMemory and records all reads
type MemoryRecorder struct {
	rm         io.ReaderAt
	pid        int
	auxv       []byte
	recordings map[uint64][]byte
	logReads   bool
}

type RecordedRead struct {
	Address uint64 `json:"addr"`
	Data    []byte `json:"data"`
	Size    int    `json:"size"`
}

type RecordingData struct {
	Reads []RecordedRead `json:"reads"`
	// Metadata about the process
	PID  int             `json:"pid"`
	Auxv []byte          `json:"auxv"`
}

func NewMemoryRecorder(rm io.ReaderAt, pid int, logReads bool) (*MemoryRecorder, error) {
	auxv, err := os.ReadFile(fmt.Sprintf("/proc/%d/auxv", pid))
	if err != nil {
		return nil, err
	}
	return &MemoryRecorder{
		rm:         rm,
		pid:        pid,
		auxv:       auxv,
		recordings: make(map[uint64][]byte),
		logReads:   logReads,
	}, nil
}

func (mr *MemoryRecorder) ReadAt(p []byte, off int64) (n int, err error) {
	addr := uint64(off)

	if mr.logReads {
		fmt.Printf("Reading at %X (size: %d)\n", addr, len(p))
	}

	// Perform the actual read
	n, err = mr.rm.ReadAt(p, off)

	// Record successful reads
	if err == nil && n > 0 {
		// Store a copy of the data
		data := make([]byte, n)
		copy(data, p[:n])
		mr.recordings[addr] = data
	}

	return n, err
}

func (mr *MemoryRecorder) GetRecording() RecordingData {
	rd := RecordingData{
		Reads: make([]RecordedRead, 0, len(mr.recordings)),
		PID:   mr.pid,
		Auxv:  mr.auxv,
	}

	for addr, data := range mr.recordings {
		rd.Reads = append(rd.Reads, RecordedRead{
			Address: addr,
			Data:    data,
			Size:    len(data),
		})
	}

	return rd
}

func (mr *MemoryRecorder) SaveToFile() error {
	data := mr.GetRecording()

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	// TODO gzip encode
	return os.WriteFile(fmt.Sprintf("testdata/memory_recording_%d.json", mr.pid), jsonData, 0644)
}

// ReplayMemory implements RemoteMemory using recorded data
type ReplayMemory struct {
	reads  map[uint64][]byte
	ranges []memRange // Sorted list of address ranges for efficient lookup
	auxv   []byte
	pid    int
	debug  bool
}

type memRange struct {
	start uint64
	end   uint64
	data  []byte
}

func NewReplayMemory(recordings RecordingData) *ReplayMemory {
	rm := &ReplayMemory{
		reads:  make(map[uint64][]byte),
		ranges: make([]memRange, 0),
		auxv:   recordings.Auxv,
		pid:    recordings.PID,
	}

	// Build the memory map
	for _, read := range recordings.Reads {
		rm.reads[read.Address] = read.Data

		// Create a range for efficient lookup
		rm.ranges = append(rm.ranges, memRange{
			start: read.Address,
			end:   read.Address + uint64(len(read.Data)),
			data:  read.Data,
		})
	}

	// Sort ranges for binary search
	sort.Slice(rm.ranges, func(i, j int) bool {
		return rm.ranges[i].start < rm.ranges[j].start
	})

	// Merge overlapping ranges for efficiency
	rm.mergeRanges()

	return rm
}

func (rm *ReplayMemory) mergeRanges() {
	if len(rm.ranges) <= 1 {
		return
	}

	merged := []memRange{rm.ranges[0]}

	for i := 1; i < len(rm.ranges); i++ {
		last := &merged[len(merged)-1]
		curr := rm.ranges[i]

		// If current range overlaps or is adjacent to last
		if curr.start <= last.end {
			// Extend the last range
			if curr.end > last.end {
				// Combine the data
				newData := make([]byte, curr.end-last.start)
				copy(newData, last.data)
				copy(newData[curr.start-last.start:], curr.data)
				last.data = newData
				last.end = curr.end
			}
		} else {
			merged = append(merged, curr)
		}
	}

	rm.ranges = merged
}

func (rm *ReplayMemory) ReadAt(p []byte, off int64) (n int, err error) {
	addr := uint64(off)

	if rm.debug {
		fmt.Printf("ReplayMemory: Reading at %X (size: %d)\n", addr, len(p))
	}

	// First check exact address match
	if data, ok := rm.reads[addr]; ok {
		copy(p, data)
		return len(data), nil
	}

	// Binary search for range containing this address
	idx := sort.Search(len(rm.ranges), func(i int) bool {
		return rm.ranges[i].end > addr
	})

	if idx < len(rm.ranges) && rm.ranges[idx].start <= addr {
		r := rm.ranges[idx]
		offset := addr - r.start
		available := uint64(len(r.data)) - offset
		toRead := uint64(len(p))
		if toRead > available {
			toRead = available
		}

		copy(p, r.data[offset:offset+toRead])
		return int(toRead), nil
	}

	if rm.debug {
		fmt.Printf("ReplayMemory: No data for address %X\n", addr)
	}
	return 0, io.EOF
}

func LoadReplayMemory(filename string) (*ReplayMemory, error) {
	compressed, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		return nil, err
	}

	// Try to decode as JSON first
	var recording RecordingData
	if err := json.Unmarshal(decompressed, &recording); err != nil {
		return nil, err
	}

	return NewReplayMemory(recording), nil
}

func ProcessInspectorTest(t *testing.T) {
	tests := []struct {
		desc           string
		file           string
		expectedModule int
		expectedLibs   []libraryInfo
		expectedLibc   libcType
	}{
		{
			desc:           "it works with jemalloc",
			file:           "testdata/memory_recording_1735824.json.gz",
			expectedModule: 2,
			expectedLibs:   []libraryInfo{libraryInfo{name: "", path: "", baseAddress: 0xae58dab90000, isVirtual: false, loadOrder: 0, hasTLS: false}, libraryInfo{name: "linux-vdso.so.1", path: "linux-vdso.so.1", baseAddress: 0xe3f7d62cb000, isVirtual: true, loadOrder: 1, hasTLS: false}, libraryInfo{name: "libjemalloc.so", path: "/usr/lib/aarch64-linux-gnu/libjemalloc.so", baseAddress: 0xe3f7d6170000, isVirtual: false, loadOrder: 2, hasTLS: true}, libraryInfo{name: "libruby.so.3.4", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/libruby.so.3.4", baseAddress: 0xe3f7d5a00000, isVirtual: false, loadOrder: 3, hasTLS: true}, libraryInfo{name: "libz.so.1", path: "/lib/aarch64-linux-gnu/libz.so.1", baseAddress: 0xe3f7d6130000, isVirtual: false, loadOrder: 4, hasTLS: false}, libraryInfo{name: "libcrypt.so.1", path: "/lib/aarch64-linux-gnu/libcrypt.so.1", baseAddress: 0xe3f7d60e0000, isVirtual: false, loadOrder: 5, hasTLS: false}, libraryInfo{name: "libm.so.6", path: "/lib/aarch64-linux-gnu/libm.so.6", baseAddress: 0xe3f7d5950000, isVirtual: false, loadOrder: 6, hasTLS: false}, libraryInfo{name: "libc.so.6", path: "/lib/aarch64-linux-gnu/libc.so.6", baseAddress: 0xe3f7d5790000, isVirtual: false, loadOrder: 7, hasTLS: true}, libraryInfo{name: "ld-linux-aarch64.so.1", path: "/lib/ld-linux-aarch64.so.1", baseAddress: 0xe3f7d628e000, isVirtual: false, loadOrder: 8, hasTLS: false}, libraryInfo{name: "libstdc++.so.6", path: "/lib/aarch64-linux-gnu/libstdc++.so.6", baseAddress: 0xe3f7d5400000, isVirtual: false, loadOrder: 9, hasTLS: true}, libraryInfo{name: "libgcc_s.so.1", path: "/lib/aarch64-linux-gnu/libgcc_s.so.1", baseAddress: 0xe3f7d60a0000, isVirtual: false, loadOrder: 10, hasTLS: true}, libraryInfo{name: "encdb.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/enc/encdb.so", baseAddress: 0xe3f7d56a0000, isVirtual: false, loadOrder: 11, hasTLS: false}, libraryInfo{name: "transdb.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/enc/trans/transdb.so", baseAddress: 0xe3f7d4fc0000, isVirtual: false, loadOrder: 12, hasTLS: false}, libraryInfo{name: "monitor.so", path: "/home/dalehamel.linux/.rubies/ruby-3.4.5/lib/ruby/3.4.0/aarch64-linux/monitor.so", baseAddress: 0xe3f7d4ba0000, isVirtual: false, loadOrder: 13, hasTLS: false}},
			expectedLibc:   libcGlibc,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			replay, err := LoadReplayMemory(tt.file)
			require.NoError(t, err)
			oldFs := fs
			defer func() {
				fs = oldFs
			}()
			fs = afero.NewMemMapFs()
			afero.WriteFile(fs, fmt.Sprintf("/proc/%d/auxv", replay.pid), replay.auxv, 0644)

			inspector, err := newProcessInspector(replay.pid, replay)

			id, err := inspector.findTLSModuleID("libruby.so")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedModule, id)

			libs, err := inspector.getLoadedLibraries()
			require.NoError(t, err)
			assert.Equal(t, tt.expectedLibs, libs)

			libc := detectLibc(libs)
			assert.Equal(t, tt.expectedLibc, libc)
		})
	}
}

func recordProcess(t *testing.T, pid int) {
	rm := remotememory.NewProcessVirtualMemory(libpf.PID(pid))
	recorder, err := NewMemoryRecorder(rm, pid, false)
	require.NoError(t, err)

	inspector, err := newProcessInspector(pid, recorder)
	require.NoError(t, err)

	id, err := inspector.findTLSModuleID("libruby.so")
	require.NoError(t, err)

	fmt.Printf("TLS module ID %d\n", id)
	libs, err := inspector.getLoadedLibraries()
	require.NoError(t, err)
	fmt.Printf("libraryInfo: %+v\n", libs)
	libc := detectLibc(libs)
	fmt.Printf("libc: %+v\n", libc)

	require.NoError(t, recorder.SaveToFile())
}

func TestProcessVirtualMemory(t *testing.T) {
	if pidStr := os.Getenv("RECORD_PID"); pidStr != "" {
		if runtime.GOOS != "linux" {
			t.Skipf("unsupported os %s", runtime.GOOS)
		}
		pid, err := strconv.Atoi(pidStr)
		require.NoError(t, err)
		recordProcess(t, pid)
	}
	ProcessInspectorTest(t)
}
