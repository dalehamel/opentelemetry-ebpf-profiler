// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/bits"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const (
	// iseqCacheSize is the LRU size for caching Ruby instruction sequences for an interpreter.
	// This should reflect the number of hot functions that are seen often in a trace.
	iseqCacheSize = 8192
	// cmeCacheSize
	cmeCacheSize = 8192
	// addrToStringSize is the LRU size for caching Ruby VM addresses to Ruby strings.
	addrToStringSize = 1024

	// rubyInsnInfoSizeLimit defines the limit up to which we will allocate memory for the
	// binary search algorithm to get the line number.
	rubyInsnInfoSizeLimit = 1 * 1024 * 1024
)

//nolint:lll
const (

	//RUBY_T_CLASS
	rubyTClass = 0x2
	//https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L114

	//RUBY_T_MODULE
	// https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L115C5-L115C74
	rubyTModule = 0x3

	//RUBY_T_ICLASS
	//https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L138
	rubyTIClass = 0x1c

	// RUBY_T_STRING
	// https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L117
	rubyTString = 0x5

	// RUBY_T_ARRAY
	// https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L119
	rubyTArray = 0x7

	// RUBY_T_MASK
	// https://github.com/ruby/ruby/blob/c149708018135595b2c19c5f74baf9475674f394/include/ruby/internal/value_type.h#L142
	rubyTMask = 0x1f

	// RSTRING_NOEMBED
	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/include/ruby/ruby.h#L978
	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/include/ruby/ruby.h#L855
	// 1 << 13
	rstringNoEmbed = 8192

	// RARRAY_EMBED_FLAG
	rarrayEmbed = 8192

	// PATHOBJ_REALPATH
	pathObjRealPathIdx = 1
)

const (
	VM_ENV_DATA_INDEX_ME_CREF = 2 * 8 // FIXME don't just multiply by 8
	VM_ENV_DATA_INDEX_SPECVAL = 1 * 8
	VM_ENV_FLAG_LOCAL         = 0x02

	// https://github.com/ruby/ruby/blob/1d1529629ce1550fad19c2d9410c4bf4995230d2/include/ruby/internal/fl_type.h#L158
	RUBY_FL_USHIFT = 12
	// https://github.com/ruby/ruby/blob/1d1529629ce1550fad19c2d9410c4bf4995230d2/include/ruby/internal/fl_type.h#L323-L324
	RUBY_FL_USER1 = 1 << (RUBY_FL_USHIFT + 1)

	// Used for computing embed array flag
	RUBY_FL_USER3 = 1 << (RUBY_FL_USHIFT + 3)
	RUBY_FL_USER4 = 1 << (RUBY_FL_USHIFT + 4)
	RUBY_FL_USER5 = 1 << (RUBY_FL_USHIFT + 5)
	RUBY_FL_USER6 = 1 << (RUBY_FL_USHIFT + 6)
	RUBY_FL_USER7 = 1 << (RUBY_FL_USHIFT + 7)
	RUBY_FL_USER8 = 1 << (RUBY_FL_USHIFT + 8)
	RUBY_FL_USER9 = 1 << (RUBY_FL_USHIFT + 9)

	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L102
	RARRAY_EMBED_FLAG = RUBY_FL_USER1

	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L114-L115
	RARRAY_EMBED_LEN_MASK = RUBY_FL_USER9 | RUBY_FL_USER8 | RUBY_FL_USER7 | RUBY_FL_USER6 |
		RUBY_FL_USER5 | RUBY_FL_USER4 | RUBY_FL_USER3

	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L122-L125
	RARRAY_EMBED_LEN_SHIFT = RUBY_FL_USHIFT + 3

	// https://github.com/ruby/ruby/blob/1d1529629ce1550fad19c2d9410c4bf4995230d2/include/ruby/internal/fl_type.h#L394
	RUBY_FL_SINGLETON = RUBY_FL_USER1

	IMEMO_MASK = 0x0f
	IMEMO_CREF = 1 /*!< class reference */
	IMEMO_SVAR = 2 /*!< special variable */
	IMEMO_MENT = 6
)

var (
	// regex to identify the Ruby interpreter executable
	rubyRegex = regexp.MustCompile(`^(?:.*/)?libruby(?:-.*)?\.so\.(\d)\.(\d)\.(\d)$`)
	// regex to extract a version from a string
	rubyVersionRegex = regexp.MustCompile(`^(\d)\.(\d)\.(\d)$`)

	rubyProcessDied   = libpf.Intern("PROCESS_DIED")
	rubyDeadFile      = libpf.Intern("<dead>")
	rubyJitDummyFrame = libpf.Intern("UNKNOWN JIT CODE")
	rubyJitDummyFile  = libpf.Intern("<jitted code>")
	rubyGcRunning     = libpf.Intern("GC_RUNNING")
	rubyGcMarking     = libpf.Intern("GC_MARKING")
	rubyGcSweeping    = libpf.Intern("GC_SWEEPING")
	rubyGcCompacting  = libpf.Intern("GC_COMPACTING")
	rubyGcDummyFile   = libpf.Intern("gc.c")

	// compiler check to make sure the needed interfaces are satisfied
	_ interpreter.Data     = &rubyData{}
	_ interpreter.Instance = &rubyInstance{}
)

//nolint:lll
type rubyData struct {
	// currentCtxPtr is the `ruby_current_execution_context_ptr` symbol value which is needed by the
	// eBPF program to build ruby backtraces.
	currentCtxPtr libpf.Address

	currentEcTlsOffset uint64

	// Address to global symbols, for id to string mappings
	globalSymbolsAddr libpf.Address
	// version of the currently used Ruby interpreter.
	// major*0x10000 + minor*0x100 + release (e.g. 3.0.1 -> 0x30001)
	version uint32

	// vmStructs reflects the Ruby internal names and offsets of named fields.
	vmStructs struct {
		// rb_execution_context_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L843
		execution_context_struct struct {
			vm_stack, vm_stack_size, cfp, thread_ptr uint8
		}

		// https://github.com/ruby/ruby/blob/v3_4_5/vm_core.h#L1108
		thread_struct struct {
			vm uint8
		}

		// https://github.com/ruby/ruby/blob/v3_4_5/vm_core.h#L666
		vm_struct struct {
			gc_objspace uint16
		}

		// https://github.com/ruby/ruby/blob/v3_4_5/gc/default/default.c#L445
		objspace struct {
			flags         uint8
			size_of_flags uint8
		}

		// rb_control_frame_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L760
		control_frame_struct struct {
			pc, iseq, ep                 uint8
			size_of_control_frame_struct uint8
		}

		// rb_iseq_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L456
		iseq_struct struct {
			body uint8
		}

		// rb_iseq_constant_body
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L311
		iseq_constant_body struct {
			iseq_type, encoded, size, location, insn_info_body, insn_info_size, succ_index_table uint8
			local_iseq, size_of_iseq_constant_body                                               uint16
		}

		// rb_iseq_location_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L272
		iseq_location_struct struct {
			pathobj, base_label, label uint8
		}

		// succ_index_table_struct
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3420
		succ_index_table_struct struct {
			small_block_ranks, block_bits, succ_part, succ_dict_block uint8
			size_of_succ_dict_block                                   uint8
		}

		// iseq_insn_info_entry
		// https://github.com/ruby/ruby/blob/4e0a512972cdcbfcd5279f1a2a81ba342ed75b6e/iseq.h#L212
		iseq_insn_info_entry struct {
			position, line_no                                               uint8
			size_of_position, size_of_line_no, size_of_iseq_insn_info_entry uint8
		}

		// RString
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/include/ruby/ruby.h#L988
		// https://github.com/ruby/ruby/blob/86ac17efde6cf98903513cac2538b15fc4ac80b2/include/ruby/internal/core/rstring.h#L196
		rstring_struct struct {
			// NOTE: starting with Ruby 3.1 the `as.ary` field is now `as.embed.ary`
			as_heap_ptr, as_ary uint8
		}

		// RArray
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/include/ruby/ruby.h#L1048
		rarray_struct struct {
			as_heap_ptr, as_ary uint8
		}

		// size_of_immediate_table holds the size of the macro IMMEDIATE_TABLE_SIZE as defined in
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3418
		size_of_immediate_table uint8

		// size_of_value holds the size of the macro VALUE as defined in
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L1136
		size_of_value uint8

		// rb_ractor_struct
		// https://github.com/ruby/ruby/blob/5ce0d2aa354eb996cb3ca9bb944f880ff6acfd57/ractor_core.h#L82
		rb_ractor_struct struct {
			running_ec uint16
		}

		// TODO add links to the structs
		// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/method.h#L63-L69
		rb_method_entry_struct struct {
			flags, defined_class, def, owner uint8
		}

		rclass_and_rb_classext_t struct {
			classext uint8
		}

		rb_classext_struct struct {
			classpath, as_singleton_class_attached_object uint8
		}

		rb_method_definition_struct struct {
			method_type, body, original_id uint8
		}

		rb_method_iseq_struct struct {
			iseqptr uint8
		}
	}
}

func rubyVersion(major, minor, release uint32) uint32 {
	return major*0x10000 + minor*0x100 + release
}

func (r *rubyData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {

	tlsModuleOffset := uint8(1) // 1 is a sensible default, libruby will usually be first lib unless LD_PRELOAD

	// if we cannot detect, assume glibc size for glibc is 16,
	dtvEntryStep := uint8(16)

	inspector, err := newProcessInspector(int(pid), rm)
	if err != nil {
		log.Errorf("failed to inspect target process for runtime linker info: %v", err)
	} else {
		id, err := inspector.findTLSModuleID("libruby.so") // TODO don't hardcode?
		if err != nil {
			log.Errorf("failed to determine loaded libs %v", err)
			return nil, err
		} else {
			log.Debugf("Detected module ID %d", id)
			tlsModuleOffset = uint8(id)
		}
		libs, err := inspector.getLoadedLibraries()
		if err != nil {
			log.Errorf("failed to determine loaded libs %v", err)
		} else {
			libc := detectLibc(libs)
			log.Debugf("Detected libc as %s", libc)
			switch libc {
			case libcGlibc:
				// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/generic/dl-dtv.h#l22
				dtvEntryStep = uint8(16)
			case libcMusl:
				// https://github.com/bminor/musl/blob/master/src/internal/pthread_impl.h#L23
				dtvEntryStep = uint8(8)
			default:
				log.Warnf("Unable to detect DTV step from libc type %s", libc)
			}
		}
	}

	cdata := support.RubyProcInfo{
		Version: r.version,

		Current_ctx_ptr:       uint64(r.currentCtxPtr + bias),
		Current_ec_tls_offset: r.currentEcTlsOffset,
		Tls_module_index:      tlsModuleOffset,
		Dtv_entry_step:        dtvEntryStep,

		Vm_stack:      r.vmStructs.execution_context_struct.vm_stack,
		Vm_stack_size: r.vmStructs.execution_context_struct.vm_stack_size,
		Cfp:           r.vmStructs.execution_context_struct.cfp,
		Thread_ptr:    r.vmStructs.execution_context_struct.thread_ptr,

		Thread_vm:   r.vmStructs.thread_struct.vm,
		Vm_objspace: r.vmStructs.vm_struct.gc_objspace,

		Objspace_flags:         r.vmStructs.objspace.flags,
		Objspace_size_of_flags: r.vmStructs.objspace.size_of_flags,

		Pc:                           r.vmStructs.control_frame_struct.pc,
		Iseq:                         r.vmStructs.control_frame_struct.iseq,
		Ep:                           r.vmStructs.control_frame_struct.ep,
		Size_of_control_frame_struct: r.vmStructs.control_frame_struct.size_of_control_frame_struct,

		Body:           r.vmStructs.iseq_struct.body,
		Cme_method_def: r.vmStructs.rb_method_entry_struct.def,

		Size_of_value: r.vmStructs.size_of_value,

		Running_ec: r.vmStructs.rb_ractor_struct.running_ec,
	}

	if err := ebpf.UpdateProcData(libpf.Ruby, pid, unsafe.Pointer(&cdata)); err != nil {
		return nil, err
	}

	iseqBodyPCToFunction, err := freelru.New[rubyIseqBodyPC, *rubyIseq](iseqCacheSize,
		hashRubyIseqBodyPC)
	if err != nil {
		return nil, err
	}

	cmeCache, err := freelru.New[libpf.Address, *rubyCme](cmeCacheSize,
		hashCme)
	if err != nil {
		return nil, err
	}

	addrToString, err := freelru.New[libpf.Address, libpf.String](addrToStringSize,
		libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	log.Debugf("Bias is 0x%08x, global_symbols are 0x%08x, relocated xs 0x%08x", bias, r.globalSymbolsAddr, bias+r.globalSymbolsAddr)

	return &rubyInstance{
		r:                 r,
		rm:                rm,
		procInfo:          cdata,
		globalSymbolsAddr: r.globalSymbolsAddr + bias,
		// TODO - we can probably just rely on the frame cache added in
		// https://github.com/open-telemetry/opentelemetry-ebpf-profiler/commit/97be3669b0f0d66f52ff9d6d33cd482f4eddb6d6
		cmeCache:             cmeCache,
		iseqBodyPCToFunction: iseqBodyPCToFunction,
		addrToString:         addrToString,
		mappings:             make(map[process.Mapping]*uint32),
		prefixes:             make(map[lpm.Prefix]*uint32),
		memPool: sync.Pool{
			New: func() any {
				buf := make([]byte, 512)
				return &buf
			},
		},
	}, nil
}

func (r *rubyData) Unload(_ interpreter.EbpfHandler) {
}

// rubyIseqBodyPC holds a reported address to a iseq_constant_body and Ruby VM program counter
// combination and is used as key in the cache.
type rubyIseqBodyPC struct {
	addr libpf.Address
	pc   uint64
}

func hashRubyIseqBodyPC(iseq rubyIseqBodyPC) uint32 {
	h := iseq.addr.Hash()
	h ^= hash.Uint64(iseq.pc)
	return uint32(h)
}

func hashCme(cme libpf.Address) uint32 {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(cme)&0xFFFFFFFFFFFF)
	return crc32.ChecksumIEEE(buf[:6])
}

// rubyIseq stores information extracted from a iseq_constant_body struct.
type rubyCme struct {
	// classname for the
	classPath libpf.String

	// method id for CMEs containing cfuncs
	methodName libpf.String

	// filename (currently only a dummy one for cfuncs)
	sourceFile libpf.String

	cframe bool

	singleton bool

	iseq rubyIseq
}

// rubyIseq stores information extracted from a iseq_constant_body struct.
type rubyIseq struct {
	// sourceFileName is the extracted filename field
	sourceFileName libpf.String

	// label
	label libpf.String

	// functionName is the function name for this sequence
	functionName libpf.String

	// line of code in source file for this instruction sequence
	line libpf.SourceLineno
}

type rubyInstance struct {
	interpreter.InstanceStubs

	// Ruby symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64

	r  *rubyData
	rm remotememory.RemoteMemory

	procInfo          support.RubyProcInfo
	globalSymbolsAddr libpf.Address
	// iseqBodyPCToFunction maps an address and Ruby VM program counter combination to extracted
	// information from a Ruby instruction sequence object.
	iseqBodyPCToFunction *freelru.LRU[rubyIseqBodyPC, *rubyIseq]

	// cmeCache maps a CME address to the symbolized info
	cmeCache *freelru.LRU[libpf.Address, *rubyCme]

	// Ruby JIT mappings
	jitMap *PerfMap
	// addrToString maps an address to an extracted Ruby String from this address.
	addrToString *freelru.LRU[libpf.Address, libpf.String]

	// memPool provides pointers to byte arrays for efficient memory reuse.
	memPool sync.Pool

	// maxSize is the largest number we did see in the last reporting interval for size
	// in getRubyLineNo.
	maxSize atomic.Uint32

	// mappings is indexed by the Mapping to its generation
	mappings map[process.Mapping]*uint32
	// prefixes is indexed by the prefix added to ebpf maps (to be cleaned up) to its generation
	prefixes map[lpm.Prefix]*uint32
	// mappingGeneration is the current generation (so old entries can be pruned)
	mappingGeneration uint32
}

func (r *rubyInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.Ruby, pid)
}

// readRubyArrayDataPtr obtains the data pointer of a Ruby array (RArray).
//
// https://github.com/ruby/ruby/blob/95aff2146/include/ruby/internal/core/rarray.h#L87
func (r *rubyInstance) readRubyArrayDataPtr(addr libpf.Address) (libpf.Address, error) {
	flags := r.rm.Ptr(addr)
	if flags&rubyTMask != rubyTArray {
		return 0, fmt.Errorf("object at 0x%08X is not an array", addr)
	}

	vms := &r.r.vmStructs
	if flags&rarrayEmbed == rarrayEmbed {
		return addr + libpf.Address(vms.rarray_struct.as_ary), nil
	}

	p := r.rm.Ptr(addr + libpf.Address(vms.rarray_struct.as_heap_ptr))
	if p != 0 {
		return 0, fmt.Errorf("heap pointer of array at 0x%08X is 0", addr)
	}

	return addr, nil
}

// readPathObjRealPath reads the realpath field from a Ruby iseq pathobj.
//
// Path objects are represented as either a Ruby string (RString) or a
// Ruby arrays (RArray) with 2 entries. The first field contains a relative
// path, the second one an absolute one. All Ruby types start with an RBasic
// object that contains a type tag that we can use to determine what variant
// we're dealing with.
//
// https://github.com/ruby/ruby/blob/4e0a51297/iseq.c#L217
// https://github.com/ruby/ruby/blob/95aff2146/vm_core.h#L267
// https://github.com/ruby/ruby/blob/95aff2146/vm_core.h#L283
// https://github.com/ruby/ruby/blob/7127f39ba/vm_core.h#L321-L321
func (r *rubyInstance) readPathObjRealPath(addr libpf.Address) (string, error) {
	flags := r.rm.Ptr(addr)
	switch flags & rubyTMask {
	case rubyTString:
		return r.readRubyString(addr)
	case rubyTArray:
		vms := &r.r.vmStructs
		arrData, e := r.readRubyArrayDataPtr(addr)
		if e != nil {
			return "", e
		}
		relVal := r.rm.Ptr(arrData + 0*libpf.Address(vms.size_of_value))
		absVal := r.rm.Ptr(arrData + 1*libpf.Address(vms.size_of_value))
		var relTag, absTag uint64
		if relVal != 0 {
			relTag = uint64(r.rm.Ptr(relVal)) & uint64(rubyTMask)
		}
		if absVal != 0 {
			absTag = uint64(r.rm.Ptr(absVal)) & uint64(rubyTMask)
		}

		var candidate libpf.Address
		if absVal != 0 && absTag == uint64(rubyTString) {
			candidate = absVal
		} else if relVal != 0 && relTag == uint64(rubyTString) {
			candidate = relVal
		} else {
			return "", fmt.Errorf("pathobj array has no string entries: relTag=0x%x absTag=0x%x", relTag, absTag)
		}

		return r.readRubyString(candidate)
	default:
		return "", fmt.Errorf("unexpected pathobj type tag: 0x%X", flags&rubyTMask)
	}
}

// readRubyString extracts a Ruby string from the given addr.
//
// 2.5.0: https://github.com/ruby/ruby/blob/4e0a51297/include/ruby/ruby.h#L1004
// 3.0.0: https://github.com/ruby/ruby/blob/48b94b791/include/ruby/internal/core/rstring.h#L73
func (r *rubyInstance) readRubyString(addr libpf.Address) (string, error) {
	flags := r.rm.Ptr(addr)
	if flags&rubyTMask != rubyTString {
		return "", fmt.Errorf("object at 0x%08X is not a string", addr)
	}

	var str string
	vms := &r.r.vmStructs
	if flags&rstringNoEmbed == rstringNoEmbed {
		str = r.rm.StringPtr(addr + libpf.Address(vms.rstring_struct.as_heap_ptr))
	} else {
		str = r.rm.String(addr + libpf.Address(vms.rstring_struct.as_ary))
	}

	r.addrToString.Add(addr, libpf.Intern(str))
	return str, nil
}

type StringReader = func(address libpf.Address) (string, error)

// getStringCached retrieves a string from cache or reads and inserts it if it's missing.
func (r *rubyInstance) getStringCached(addr libpf.Address, reader StringReader) (
	libpf.String, error) {
	if value, ok := r.addrToString.Get(addr); ok {
		return value, nil
	}

	str, err := reader(addr)
	if err != nil {
		return libpf.NullString, err
	}
	if !util.IsValidString(str) {
		log.Debugf("Extracted invalid string from Ruby at 0x%x, len=%d, bytes=%x",
			addr, len(str), []byte(str))
		return libpf.NullString, fmt.Errorf("extracted invalid Ruby string from address 0x%x", addr)
	}

	val := libpf.Intern(str)
	r.addrToString.Add(addr, val)
	return val, err
}

// rubyPopcount64 is a helper macro.
// Ruby makes use of __builtin_popcount intrinsics. These builtin intrinsics are not available
// here so we use the equivalent function of the Go standard library.
// https://github.com/ruby/ruby/blob/48b94b791997881929c739c64f95ac30f3fd0bb9/internal/bits.h#L408
func rubyPopcount64(in uint64) uint32 {
	return uint32(bits.OnesCount64(in))
}

// smallBlockRankGet is a helper macro.
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3432
func smallBlockRankGet(v uint64, i uint32) uint32 {
	if i == 0 {
		return 0
	}
	return uint32((v >> ((i - 1) * 9))) & 0x1ff
}

// immBlockRankGet is a helper macro.
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3430
func immBlockRankGet(v uint64, i uint32) uint32 {
	tmp := v >> (i * 7)
	return uint32(tmp) & 0x7f
}

// getObsoleteRubyLineNo implements a binary search algorithm to get the line number for a position.
//
// Implementation according to Ruby:
// https://github.com/ruby/ruby/blob/4e0a512972cdcbfcd5279f1a2a81ba342ed75b6e/iseq.c#L1254-L1295
func (r *rubyInstance) getObsoleteRubyLineNo(iseqBody libpf.Address,
	pos, size uint32) (uint32, error) {
	vms := &r.r.vmStructs
	sizeOfEntry := uint32(vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry)

	ptr := r.rm.Ptr(iseqBody + libpf.Address(vms.iseq_constant_body.insn_info_body))
	syncPoolData := r.memPool.Get().(*[]byte)
	if syncPoolData == nil {
		return 0, errors.New("failed to get memory from sync pool")
	}
	if uint32(len(*syncPoolData)) < size*sizeOfEntry {
		// make sure the data we want to write into blob fits in
		*syncPoolData = make([]byte, size*sizeOfEntry)
	}
	defer func() {
		// Reset memory and return it for reuse.
		for i := uint32(0); i < size*sizeOfEntry; i++ {
			(*syncPoolData)[i] = 0x0
		}
		r.memPool.Put(syncPoolData)
	}()
	blob := (*syncPoolData)[:size*sizeOfEntry]

	// Read the table with multiple iseq_insn_info_entry entries only once for the binary search.
	if err := r.rm.Read(ptr, blob); err != nil {
		return 0, fmt.Errorf("failed to read line table for binary search: %v", err)
	}

	var blobPos uint32
	var entryPos, entryLine uint32
	right := size - 1
	left := uint32(1)

	posOffset := uint32(vms.iseq_insn_info_entry.position)
	posSize := uint32(vms.iseq_insn_info_entry.size_of_position)
	lineNoOffset := uint32(vms.iseq_insn_info_entry.line_no)
	lineNoSize := uint32(vms.iseq_insn_info_entry.size_of_line_no)

	for left <= right {
		index := left + (right-left)/2

		blobPos = index * sizeOfEntry

		entryPos = binary.LittleEndian.Uint32(
			blob[blobPos+posOffset : blobPos+posOffset+posSize])
		entryLine = binary.LittleEndian.Uint32(
			blob[blobPos+lineNoOffset : blobPos+lineNoOffset+lineNoSize])

		if entryPos == pos {
			return entryLine, nil
		}

		if entryPos < pos {
			left = index + 1
			continue
		}
		right = index - 1
	}

	if left >= size {
		blobPos = (size - 1) * sizeOfEntry
		return binary.LittleEndian.Uint32(
			blob[blobPos+lineNoOffset : blobPos+lineNoOffset+lineNoSize]), nil
	}

	blobPos = left * sizeOfEntry
	entryPos = binary.LittleEndian.Uint32(blob[blobPos+posOffset : blobPos+posOffset+posSize])

	if entryPos > pos {
		blobPos = (left - 1) * sizeOfEntry
		return binary.LittleEndian.Uint32(
			blob[blobPos+lineNoOffset : blobPos+lineNoOffset+lineNoSize]), nil
	}
	return binary.LittleEndian.Uint32(
		blob[blobPos+lineNoOffset : blobPos+lineNoOffset+lineNoSize]), nil
}

// getRubyLineNo extracts the line number information from the given instruction sequence body and
// Ruby VM program counter.
// Starting with Ruby version 2.6.0 [0] Ruby no longer stores the information about the line number
// in a struct field but encodes them in a succinct data structure [1].
// For the lookup of the line number in this data structure getRubyLineNo follows the naming and
// implementation of the Ruby internal function succ_index_lookup [2].
//
// [0] https://github.com/ruby/ruby/commit/83262f24896abeaf1977c8837cbefb1b27040bef
// [1] https://en.wikipedia.org/wiki/Succinct_data_structure
// [2] https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3500-L3517
func (r *rubyInstance) getRubyLineNo(iseqBody libpf.Address, pc uint64) (uint32, error) {
	vms := &r.r.vmStructs

	// Read the struct iseq_constant_body only once.
	blob := make([]byte, vms.iseq_constant_body.size_of_iseq_constant_body)
	if err := r.rm.Read(iseqBody, blob); err != nil {
		return 0, fmt.Errorf("failed to read iseq_constant_body: %v", err)
	}

	offsetEncoded := vms.iseq_constant_body.encoded
	iseqEncoded := binary.LittleEndian.Uint64(blob[offsetEncoded : offsetEncoded+8])

	offsetSize := vms.iseq_constant_body.insn_info_size
	size := binary.LittleEndian.Uint32(blob[offsetSize : offsetSize+4])

	// For our better understanding and future improvement we track the maximum value we get for
	// size and report it.
	util.AtomicUpdateMaxUint32(&r.maxSize, size)

	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L1678
	if size == 0 {
		return 0, errors.New("failed to read size")
	}
	if size == 1 {
		offsetBody := vms.iseq_constant_body.insn_info_body
		lineNo := binary.LittleEndian.Uint32(blob[offsetBody : offsetBody+4])
		return lineNo, nil
	}
	if size > rubyInsnInfoSizeLimit {
		// When reading the value for size we don't have a way to validate this returned
		// value. To make sure we don't accept any arbitrary number we set here a limit of
		// 1MB.
		// Returning 0 here is not the correct line number at this point. But we let the
		// rest of the symbolization process unwind the frame and get the file name. This
		// way we can provide partial results.
		return 0, nil
	}

	// To get the line number iseq_encoded is subtracted from pc. This result also represents the
	// size of the current instruction sequence. If the calculated size of the instruction sequence
	// is greater than the value in iseq_encoded we don't report this pc to user space.
	//
	//nolint:lll
	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_backtrace.c#L47-L48
	pos := (pc - iseqEncoded) / uint64(vms.size_of_value)
	if pos != 0 {
		pos--
	}

	// Ruby 2.6 changed the way of storing line numbers with [0]. As we still want to get
	// the line number information for older Ruby versions, we have this special
	// handling here.
	//
	// [0] https://github.com/ruby/ruby/commit/83262f24896abeaf1977c8837cbefb1b27040bef
	if r.r.version < 0x20600 {
		return r.getObsoleteRubyLineNo(iseqBody, uint32(pos), size)
	}

	offsetSuccTable := vms.iseq_constant_body.succ_index_table
	succIndexTable := binary.LittleEndian.Uint64(blob[offsetSuccTable : offsetSuccTable+8])

	if succIndexTable == 0 {
		// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L1686
		return 0, errors.New("failed to get table with line information")
	}

	// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/iseq.c#L3500-L3517
	var tableIndex uint32
	if pos < uint64(vms.size_of_immediate_table) {
		i := int(pos / 9)
		j := int(pos % 9)
		immPart := r.rm.Uint64(libpf.Address(succIndexTable) +
			libpf.Address(i*int(vms.size_of_value)))
		if immPart == 0 {
			return 0, errors.New("failed to read immPart")
		}
		tableIndex = immBlockRankGet(immPart, uint32(j))
	} else {
		blockIndex := uint32((pos - uint64(vms.size_of_immediate_table)) / 512)
		blockOffset := libpf.Address(blockIndex *
			uint32(vms.succ_index_table_struct.size_of_succ_dict_block))

		rank := r.rm.Uint32(libpf.Address(succIndexTable) +
			libpf.Address(vms.succ_index_table_struct.succ_part) + blockOffset)
		if rank == 0 {
			return 0, errors.New("failed to read rank")
		}

		blockBitIndex := uint32((pos - uint64(vms.size_of_immediate_table)) % 512)
		smallBlockIndex := blockBitIndex / 64
		smallBlockOffset := libpf.Address(smallBlockIndex * uint32(vms.size_of_value))

		smallBlockRanks := r.rm.Uint64(libpf.Address(succIndexTable) + blockOffset +
			libpf.Address(vms.succ_index_table_struct.succ_part+
				vms.succ_index_table_struct.small_block_ranks))
		if smallBlockRanks == 0 {
			return 0, errors.New("failed to read smallBlockRanks")
		}

		smallBlockPopcount := smallBlockRankGet(smallBlockRanks, smallBlockIndex)

		blockBits := r.rm.Uint64(libpf.Address(succIndexTable) + blockOffset +
			libpf.Address(vms.succ_index_table_struct.succ_part+
				vms.succ_index_table_struct.block_bits) + smallBlockOffset)
		if blockBits == 0 {
			return 0, errors.New("failed to read blockBits")
		}
		popCnt := rubyPopcount64((blockBits << (63 - blockBitIndex%64)))

		tableIndex = rank + smallBlockPopcount + popCnt
	}
	tableIndex--

	offsetBody := vms.iseq_constant_body.insn_info_body
	lineNoAddr := binary.LittleEndian.Uint64(blob[offsetBody : offsetBody+8])
	if lineNoAddr == 0 {
		return 0, errors.New("failed to read lineNoAddr")
	}

	lineNo := r.rm.Uint32(libpf.Address(lineNoAddr) +
		libpf.Address(tableIndex*uint32(vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry)))
	if lineNo == 0 {
		return 0, errors.New("failed to read lineNo")
	}
	return lineNo, nil
}

func (r *rubyInstance) readClassName(classAddr libpf.Address) (libpf.String, bool, error) {
	var classPath libpf.String
	var classpathPtr libpf.Address
	var singleton bool
	var err error

	classFlags := r.rm.Ptr(classAddr)
	classMask := classFlags & rubyTMask

	switch classMask {
	case rubyTClass, rubyTModule:
		classpathPtr = r.rm.Ptr(classAddr + libpf.Address(r.r.vmStructs.rclass_and_rb_classext_t.classext+r.r.vmStructs.rb_classext_struct.classpath))

		// Should also check if it is a singleton
		// https://github.com/ruby/ruby/blob/b627532/vm_backtrace.c#L1934-L1937
		// https://github.com/ruby/ruby/blob/b627532/internal/class.h#L528

		if classFlags&RUBY_FL_SINGLETON != 0 {
			log.Debugf("Got singleton class")
			singleton = true
			singletonObject := r.rm.Ptr(classAddr + libpf.Address(r.r.vmStructs.rclass_and_rb_classext_t.classext+r.r.vmStructs.rb_classext_struct.as_singleton_class_attached_object))
			classpathPtr = r.rm.Ptr(singletonObject + libpf.Address(r.r.vmStructs.rclass_and_rb_classext_t.classext+r.r.vmStructs.rb_classext_struct.classpath))
		}
		// If it is neither a class nor a module, we should handle what i guess is an anonymous class?
		// https://github.com/ruby/ruby/blob/b627532/vm_backtrace.c#L1936-L1937 (see rb_class2name)

		// #define RCLASS_EXT_PRIME(c) (&((struct RClass_and_rb_classext_t*)(c))->classext)
		// #define RCLASS_ATTACHED_OBJECT(c) (RCLASS_EXT_PRIME(c)->as.singleton_class.attached_object)
	case rubyTIClass:
		//https://github.com/ruby/ruby/blob/b627532/vm_backtrace.c#L1931-L1933

		// Get the 'klass'
		// struct RBasic {
		//    VALUE                      flags;                /*     0     8 */
		//    const VALUE                klass;                /*     8     8 */
		// ...
		RBASIC_KCLASS_OFFSET := libpf.Address(8) // TODO readthis from `RBasic` struct and store on vmstructs

		if klassAddr := r.rm.Ptr(classAddr + RBASIC_KCLASS_OFFSET); klassAddr != 0 {
			log.Debugf("Using klass for iclass type")
			classpathPtr = r.rm.Ptr(klassAddr + libpf.Address(r.r.vmStructs.rclass_and_rb_classext_t.classext+r.r.vmStructs.rb_classext_struct.classpath))
		}
	default:
		return libpf.NullString, singleton, fmt.Errorf("object at 0x%08X is not a handled class (mask: %08X)", classAddr, classMask)
	}

	if classpathPtr != 0 {
		classPath, err = r.getStringCached(classpathPtr, r.readRubyString)
		if err != nil {
			return libpf.NullString, singleton, fmt.Errorf("unable to read classpath string %x %v", classpathPtr, err)
		}
	}

	return classPath, singleton, nil
}

// Aims to mimic the logic of id2str, which ultimately calls this
// https://github.com/ruby/ruby/blob/v3_4_5/symbol.c#L450-L499
func (r *rubyInstance) id2str(originalId uint64) (libpf.String, error) {
	var symbolName libpf.String
	var err error

	vms := &r.r.vmStructs

	// RUBY_ID_SCOPE_SHIFT = 4
	// https://github.com/ruby/ruby/blob/797a4115bbb249c4f5f11e1b4bacba7781c68cee/template/id.h.tmpl#L30
	RUBY_ID_SCOPE_SHIFT := 4
	// FIXME this is compiled into ruby (id.h.tmpl) as a template :lolcry: see if we can read it from gdb using gdbinit or something, but we will need a big table to find it
	lastOpId := uint64(170) // this is the value for 3.4.4+ according to rbspy

	// TODO handle differences post 3.4.6:
	//prior to 3.4.6:
	// typedef struct {
	//     rb_id_serial_t last_id; (uint32_t, 4 bytes)
	//     st_table *str_sym; (pointer, so 8 bytes?)
	//     VALUE ids; (4 + 8 = 12 offset)
	//     VALUE dsymbol_fstr_hash;
	// } rb_symbols_t;
	//after 3.4.6:
	// typedef struct {
	//     rb_atomic_t next_id; (int, probably 4 bytes)
	//     VALUE sym_set; (size of 8)
	//
	//     VALUE ids; (4 + 8 = 12 offset)
	// } rb_symbols_t;

	IDS_OFFSET := 16 // rb_id_serial_t probably gets padded to be word-aligned

	serial := originalId
	if originalId > lastOpId {
		serial = originalId >> RUBY_ID_SCOPE_SHIFT
	}

	lastId := r.rm.Uint32(r.globalSymbolsAddr)

	if serial > uint64(lastId) {
		return libpf.NullString, fmt.Errorf("invalid serial %d, greater than last id %d", serial, lastId)
	}

	ids := r.rm.Ptr(r.globalSymbolsAddr + libpf.Address(IDS_OFFSET))

	// https://github.com/ruby/ruby/blob/v3_4_5/symbol.c#L77
	ID_ENTRY_UNIT := uint64(512)

	idx := serial / ID_ENTRY_UNIT

	// string2cstring
	flags := r.rm.Ptr(ids)

	var idsPtr libpf.Address
	var idsLen uint64

	// Handle embedded arrays
	// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L297-L307
	if (flags & RARRAY_EMBED_FLAG) > 0 {
		log.Debugf("Handling embedded array with shift")
		// It is embedded, so just get the offset of as.ary
		idsPtr = r.rm.Ptr(ids + libpf.Address(vms.rarray_struct.as_ary))

		// Get the length from the flags
		// https://github.com/ruby/ruby/blob/8836f26efa7a6deb0ef8b3f253d8d53d04d43152/include/ruby/internal/core/rarray.h#L240-L242
		idsLen = uint64((flags & RARRAY_EMBED_LEN_MASK) >> RARRAY_EMBED_LEN_SHIFT)
	} else {
		idsPtr = r.rm.Ptr(ids + libpf.Address(vms.rarray_struct.as_heap_ptr))
		// NOTE assuming that len and ary are at the same location in union, this might not be valid
		// We may want to add these as separate struct fields in case this data structure changes
		idsLen = r.rm.Uint64(ids + libpf.Address(vms.rarray_struct.as_ary))
	}

	if idx > idsLen {
		return libpf.NullString, fmt.Errorf("invalid idx %d, number of ids %d", idx, idsLen)
	}

	array := r.rm.Ptr(idsPtr + libpf.Address(idx*8)) // TODO don't hardcode 8 here, we just need the word size though
	arrayPtr := r.rm.Ptr(array + libpf.Address(vms.rarray_struct.as_heap_ptr))

	flags = r.rm.Ptr(array)
	if (flags & RARRAY_EMBED_FLAG) > 0 {
		log.Debugf("Handling embedded array (2 levels) with shift")
		arrayPtr = r.rm.Ptr(array + libpf.Address(vms.rarray_struct.as_ary))
	}
	offset := (serial % 512) * 2
	stringPtr := r.rm.Ptr(arrayPtr + libpf.Address(offset*8))

	symbolName, err = r.getStringCached(stringPtr, r.readRubyString)
	if err != nil {
		log.Errorf("Unable to read string %v", err)
	}

	return symbolName, err
}

func (r *rubyInstance) PtrCheck(addr libpf.Address) (libpf.Address, error) {
	var buf [8]byte
	if err := r.rm.Read(addr, buf[:]); err != nil {
		return 0, err
	}
	return libpf.Address(binary.LittleEndian.Uint64(buf[:])) - r.rm.Bias, nil
}

// TODO refactor into cframe / iseq handlers
func (r *rubyInstance) processCmeFrame(cmeAddr libpf.Address, cmeFrameType uint8) (libpf.String, libpf.String, libpf.String, bool, bool, libpf.Address, error) {
	// Get the classpath, and figure out the iseq body offset from the definition
	// so that we can get the name and line number as below

	var classPath libpf.String
	var iseqBody libpf.Address
	var singleton bool
	var cframe bool
	var err error

	vms := &r.r.vmStructs
	//log.Debugf("Got Ruby CME frame %X", cmeAddr)

	methodDefinition, err := r.PtrCheck(cmeAddr + libpf.Address(vms.rb_method_entry_struct.def))
	if err != nil {
		return libpf.NullString, libpf.NullString, libpf.NullString, singleton, cframe, iseqBody, fmt.Errorf("Unable to read method definition, CME (%08x) %v", cmeAddr, err)
	}

	if cmeFrameType == support.RubyFrameTypeCmeCfunc {
		var cfuncName libpf.String
		cframe = true
		classDefinition := r.rm.Ptr(cmeAddr + libpf.Address(vms.rb_method_entry_struct.owner))
		classPath, singleton, err = r.readClassName(classDefinition)
		if err != nil {
			log.Errorf("Failed to read class name from owner for cfunc: %v", err)
		} else {
			log.Debugf("Got %s for cfunc owner", classPath)
		}
		originalId := r.rm.Uint64(methodDefinition + libpf.Address(vms.rb_method_definition_struct.original_id))

		cfuncName, err = r.id2str(originalId)
		log.Debugf("Got cfunc name %s", cfuncName)
		return classPath, cfuncName, libpf.Intern("<cfunc>"), singleton, cframe, iseqBody, nil
	} else {

		// TODO delete me, we should trust the values from BPF
		// We do a direct read, as a value of 0 would be mistaken for ISEQ type
		var buf [1]byte
		if r.rm.Read(methodDefinition+libpf.Address(vms.rb_method_definition_struct.method_type), buf[:]) != nil {
			return libpf.NullString, libpf.NullString, libpf.NullString, singleton, cframe, iseqBody, fmt.Errorf("Unable to read method type, CME (%08x) is corrupt, method def %08X", cmeAddr, methodDefinition)
		}

		// NOTE - it is stored in a bitfield of size 4, so we must mask with 0xF
		// https://github.com/ruby/ruby/blob/5e817f98af9024f34a3491c0aa6526d1191f8c11/method.h#L188
		methodType := buf[0] & 0xF
		log.Debugf("Method type %x", methodType)

		classDefinition := r.rm.Ptr(cmeAddr + libpf.Address(vms.rb_method_entry_struct.defined_class))
		classPath, singleton, err = r.readClassName(classDefinition)
		if err != nil {
			log.Errorf("Failed to read class name for iseq: %v", err)
		}

		methodBody := r.rm.Ptr(methodDefinition + libpf.Address(vms.rb_method_definition_struct.body))
		if methodBody == 0 {
			log.Errorf("method body was empty")
			return classPath, libpf.NullString, libpf.NullString, singleton, cframe, iseqBody, fmt.Errorf("unable to read method body, classpath: %s", classPath.String())
		}

		iseqBody = r.rm.Ptr(methodBody + libpf.Address(vms.rb_method_iseq_struct.iseqptr+vms.iseq_struct.body))

		if iseqBody == 0 {
			log.Errorf("iseq body was empty")
			return libpf.NullString, libpf.NullString, libpf.NullString, singleton, cframe, iseqBody, fmt.Errorf("unable to read iseq body")
		}
		//log.Debugf("Read CME successfully %s %08x", classPath.String(), iseqBody)
	}

	return classPath, libpf.NullString, libpf.NullString, singleton, cframe, iseqBody, nil
}

func (r *rubyInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler,
	_ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	log.Debugf("Synchronizing ruby mappings")
	pid := pr.PID()
	r.mappingGeneration++
	var jitMapping *process.Mapping
	jitFound := false
	for idx := range mappings {
		m := &mappings[idx]
		if !m.IsExecutable() || !m.IsAnonymous() {
			continue
		}
		// If prctl is allowed, ruby should label the memory region
		// always prefer that
		if strings.Contains(m.Path.String(), "jit_reserve_addr_space") {
			jitMapping = m
			jitFound = true
		}
		// Use the first executable anon region we find if it isn't labeled
		// If we find more, prefer ones earlier in memory or larger in size
		if !jitFound && (jitMapping == nil || m.Vaddr < jitMapping.Vaddr || m.Length > jitMapping.Length) {
			// Don't set jitFound here as it is a heuristic, we aren't sure
			// could be on a system without linux config flag to allow prctl to label memoy
			jitMapping = m
		}

		if _, exists := r.mappings[*m]; exists {
			*r.mappings[*m] = r.mappingGeneration
			continue
		}

		// Generate a new uint32 pointer which is shared for mapping and the prefixes it owns
		// so updating the mapping above will reflect to prefixes also.
		mappingGeneration := r.mappingGeneration
		r.mappings[*m] = &mappingGeneration

		// Just assume all anonymous and executable mappings are Ruby for now
		log.Debugf("Enabling Ruby interpreter for %#x/%#x", m.Vaddr, m.Length)

		prefixes, err := lpm.CalculatePrefixList(m.Vaddr, m.Vaddr+m.Length)
		if err != nil {
			return fmt.Errorf("new anonymous mapping lpm failure %#x/%#x", m.Vaddr, m.Length)
		}

		for _, prefix := range prefixes {
			_, exists := r.prefixes[prefix]
			if !exists {
				err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindRuby, 0, 0)
				if err != nil {
					return err
				}
			}
			r.prefixes[prefix] = &mappingGeneration
		}
	}
	if jitMapping != nil && (r.procInfo.Jit_start != jitMapping.Vaddr || r.procInfo.Jit_end != jitMapping.Vaddr+jitMapping.Length) {
		r.procInfo.Jit_start = jitMapping.Vaddr
		r.procInfo.Jit_end = jitMapping.Vaddr + jitMapping.Length
		if err := ebpf.UpdateProcData(libpf.Ruby, pr.PID(), unsafe.Pointer(&r.procInfo)); err != nil {
			return err
		}
		log.Debugf("Added jit mapping %08x ruby proc info, %08x", r.procInfo.Jit_start, r.procInfo.Jit_end)

		if r.jitMap == nil {
			// Check for jit interface here, store the path to the file so we can
			// lookup the jit PCs rather than push a dummy frame
			jitFile := fmt.Sprintf("/tmp/perf-%d.map", pr.PID())
			if _, err := os.Stat(jitFile); err != nil {
				log.Warnf("Jit mapping not found for ruby process at %s", jitFile)
			} else {
				perfMap := NewPerfMap()
				if err := perfMap.ParseFile(jitFile); err != nil {
					log.Errorf("Unable to parse perf map at %s, %v", jitFile, err)
				} else {
					log.Debugf("Loaded perf map from %s, stats: %s", jitFile, perfMap.Stats())
					r.jitMap = perfMap
				}
			}
		}
	}
	// Remove prefixes not seen
	for prefix, generationPtr := range r.prefixes {
		if *generationPtr == r.mappingGeneration {
			continue
		}
		log.Debugf("Delete Ruby prefix %#v", prefix)
		_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		delete(r.prefixes, prefix)
	}
	for m, generationPtr := range r.mappings {
		if *generationPtr == r.mappingGeneration {
			continue
		}
		log.Debugf("Disabling Ruby for %#x/%#x", m.Vaddr, m.Length)
		delete(r.mappings, m)
	}

	return nil
}

func processDied(frames *libpf.Frames) {
	frames.Append(&libpf.Frame{
		Type:         libpf.RubyFrame,
		FunctionName: rubyProcessDied,
		SourceFile:   rubyDeadFile,
		SourceLine:   0,
	})
}

func (r *rubyInstance) Symbolize(frame *host.Frame, frames *libpf.Frames) error {
	if !frame.Type.IsInterpType(libpf.Ruby) {
		return interpreter.ErrMismatchInterpreterType
	}
	vms := &r.r.vmStructs

	sfCounter := successfailurecounter.New(&r.successCount, &r.failCount)
	defer sfCounter.DefaultToFailure()

	var err error
	var cme libpf.Address
	var iseqBody libpf.Address
	var classPath libpf.String
	var methodName libpf.String
	var label libpf.String
	var sourceFile libpf.String
	var sourceLine libpf.SourceLineno
	var iseq *rubyIseq
	var singleton bool
	var cframe bool
	var cmeEntry *rubyCme
	var cmeHit bool

	frameAddr := libpf.Address(frame.File & support.RubyAddrMask48Bit)
	frameAddrType := uint8(frame.File >> 48)

	switch frameAddrType {
	case support.RubyFrameTypeCmeIseq, support.RubyFrameTypeCmeCfunc:
		cme = frameAddr

		var cmeHit bool
		cmeEntry, cmeHit = r.cmeCache.Get(cme)
		if !cmeHit {
			if _, err := r.PtrCheck(cme); err != nil && errors.Is(err, syscall.ESRCH) {
				processDied(frames)
				// Keep going in case other frames were cached
				return nil
			}
			// TODO if the process is dead and we didn't get a hit, insert a special dummy frame
			cmeEntry = &rubyCme{}
			//log.Debugf("Got ruby CME at 0x%08x", cme)
			classPath, methodName, sourceFile, singleton, cframe, iseqBody, err = r.processCmeFrame(cme, frameAddrType)
			if err != nil {
				log.Errorf("Tried and failed to process as CME frame %v", err)
			}
		} else {
			classPath = cmeEntry.classPath
			methodName = cmeEntry.methodName
			sourceFile = cmeEntry.sourceFile
			singleton = cmeEntry.singleton
			cframe = cmeEntry.cframe
		}
	case support.RubyFrameTypeIseq:
		iseqBody = libpf.Address(frameAddr)
	case support.RubyFrameTypeGc:
		gcMode := frameAddr
		var gcModeStr libpf.String
		switch gcMode {
		case support.RubyGcModeNone:
			gcModeStr = rubyGcRunning
		case support.RubyGcModeMarking:
			gcModeStr = rubyGcMarking
		case support.RubyGcModeSweeping:
			gcModeStr = rubyGcSweeping
		case support.RubyGcModeCompacting:
			gcModeStr = rubyGcCompacting
		}

		// TODO append a second frame if we are marking, sweeping, or compacting, to nest on "gcModeRunning"?
		frames.Append(&libpf.Frame{
			Type:         libpf.RubyFrame,
			FunctionName: gcModeStr,
			SourceFile:   rubyGcDummyFile,
			SourceLine:   0,
		})
		return nil
	case support.RubyFrameTypeJit:
		label := rubyJitDummyFrame
		if r.jitMap != nil {
			jitSymbol, ok, err := r.jitMap.LookupWithReload(uint64(frameAddr))
			if err != nil {
				log.Errorf("Error loading looking up jit symbol for PC %08X: %v", frameAddr, err)
			}
			if !ok {
				log.Warnf("JIT: Unable to lookup PC %08x, map stats: %s", frameAddr, r.jitMap.Stats())
			} else {
				log.Debugf("Found JIT symbol %s for PC %08X", jitSymbol.Name, frameAddr)
				label = libpf.Intern(jitSymbol.Name)
			}
		} else {
			log.Warnf("JIT: unable to symbolize, no jit mapping loaded")
		}
		frames.Append(&libpf.Frame{
			Type:         libpf.RubyFrame,
			FunctionName: label,
			SourceFile:   rubyJitDummyFile,
			SourceLine:   0,
		})
		return nil
	default:
		err = fmt.Errorf("Unable to get CME or ISEQ from frame address")
	}

	if err != nil {
		log.Errorf("Couldn't handle frame (%d) 0x%08x (pc: 0x%08x) as %d frame %08x %v", frameAddrType, frameAddr, frame.Lineno, frameAddrType, iseqBody, err)
	}

	if methodName == libpf.NullString {
		// The Ruby VM program counter that was extracted from the current call frame is embedded in
		// the Linenos field.
		pc := frame.Lineno

		key := rubyIseqBodyPC{
			addr: iseqBody,
			pc:   uint64(pc),
		}

		var ok bool

		if iseq == nil {
			iseq, ok = r.iseqBodyPCToFunction.Get(key)
		} else {
			ok = true
		}
		if !ok {
			if _, err := r.PtrCheck(iseqBody); err != nil && errors.Is(err, syscall.ESRCH) {
				processDied(frames)
				// keep symbolizing in case other frames were cached
				return nil
			}
			lineNo, err := r.getRubyLineNo(iseqBody, uint64(pc))
			if err != nil {
				lineNo = 0
				log.Warnf("RubySymbolizer: Failed to get line number (%d) %v", frameAddrType, err)
			}

			// Body used for label is indirect, need to do: iseq body -> local iseq -> iseq body
			// https://github.com/ruby/ruby/blob/v3_4_5/vm_backtrace.c#L1943
			// https://github.com/ruby/ruby/blob/v3_4_5/iseq.c#L1426
			localIseqPtr, err := r.PtrCheck(iseqBody + libpf.Address(vms.iseq_constant_body.local_iseq))
			if err != nil {
				log.Errorf("Unable to dereference local iseq: %v", err)
			}

			iseqLocalBody, err := r.PtrCheck(localIseqPtr + libpf.Address(vms.iseq_struct.body))
			if err != nil {
				log.Errorf("Unable to dereference local iseq body: %v", err)
			}

			sourceFileNamePtr := r.rm.Ptr(iseqLocalBody +
				libpf.Address(vms.iseq_constant_body.location+vms.iseq_location_struct.pathobj))
			sourceFileName, err := r.getStringCached(sourceFileNamePtr, r.readPathObjRealPath)
			if err != nil {
				sourceFileName = libpf.Intern("UNKNOWN_FILE")
				log.Warnf("RubySymbolizer: Failed to get source file name %v", err)
			}

			iseqLabelPtr := r.rm.Ptr(iseqLocalBody +
				libpf.Address(vms.iseq_constant_body.location+vms.iseq_location_struct.label))
			iseqLabel, err := r.getStringCached(iseqLabelPtr, r.readRubyString)
			if err != nil {
				iseqLabel = libpf.Intern("UNKNOWN_LABEL")
				log.Warnf("RubySymbolizer: Failed to get source base label (iseq@0x%08x) %v", iseqBody, err)
			}

			funcNamePtr := r.rm.Ptr(iseqLocalBody +
				libpf.Address(vms.iseq_constant_body.location+vms.iseq_location_struct.base_label))
			functionName, err := r.getStringCached(funcNamePtr, r.readRubyString)
			if err != nil {
				// TODO maybe don't cache entries that are unknown, in case the lookup could succeed later?
				functionName = libpf.Intern(fmt.Sprintf("UNKNOWN_FUNCTION %d %08x", frameAddrType, frame.Extra))
				log.Warnf("RubySymbolizer: Failed to get source function name (iseq@0x%08x) %v", iseqBody, err)
			}

			iseq = &rubyIseq{
				functionName:   functionName,
				label:          iseqLabel,
				sourceFileName: sourceFileName,
				line:           libpf.SourceLineno(lineNo),
			}
			key.addr = iseqBody
			r.iseqBodyPCToFunction.Add(key, iseq)
		}
		methodName = iseq.functionName
		label = iseq.label
		sourceFile = iseq.sourceFileName
		sourceLine = iseq.line
	}

	if (frameAddrType == support.RubyFrameTypeCmeIseq || frameAddrType == support.RubyFrameTypeCmeCfunc) && !cmeHit {
		cmeEntry = &rubyCme{
			classPath:  classPath,
			methodName: methodName,
			sourceFile: sourceFile,
			singleton:  singleton,
			cframe:     cframe,
		}
		if iseq != nil {
			cmeEntry.iseq = *iseq
		}
		r.cmeCache.Add(cme, cmeEntry)
	}

	// TODO we need to duplicate the exact logic of
	// rb_profile_frame_full_label
	fullLabel := profileFrameFullLabel(classPath, methodName, label, singleton, cframe)

	// Ruby doesn't provide the information about the function offset for the
	// particular line. So we report 0 for this to our backend.
	frames.Append(&libpf.Frame{
		Type:         libpf.RubyFrame,
		FunctionName: fullLabel,
		SourceFile:   sourceFile,
		SourceLine:   sourceLine,
	})
	sfCounter.ReportSuccess()
	return nil
}

func qualifiedMethodName(classPath, methodName libpf.String, singleton bool) libpf.String {
	if classPath != libpf.NullString {
		joinChar := "#"
		if singleton {
			joinChar = "."
		}
		methodName = libpf.Intern(fmt.Sprintf("%s%s%s", classPath, joinChar, methodName))
	}

	return methodName
}

// TODO this should be saved in the cache, we shouldn't unconditionally run this
func profileFrameFullLabel(classPath, baseLabel, label libpf.String, singleton, cframe bool) libpf.String {
	qualified := qualifiedMethodName(classPath, baseLabel, singleton)

	if cframe {
		return qualified
	}

	if qualified == libpf.NullString || qualified == baseLabel {
		return baseLabel
	}

	labelLength := len(label.String())
	baseLabelLength := len(baseLabel.String())
	prefixLen := labelLength - baseLabelLength

	//log.Debugf("label: %s", label.String())
	//log.Debugf("base_label: %s", baseLabel.String())
	//log.Debugf("qualified: %s", qualified.String())

	// Ensure prefixLen doesn't exceed label length (defensive programming)
	if prefixLen < 0 {
		prefixLen = 0
	}

	if prefixLen > labelLength {
		prefixLen = labelLength
	}

	// Get the prefix from label and concatenate with qualifiedMethodName
	return libpf.Intern(label.String()[:prefixLen] + qualified.String())
}

func (r *rubyInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	rubyIseqBodyPCStats := r.iseqBodyPCToFunction.ResetMetrics()
	addrToStringStats := r.addrToString.ResetMetrics()

	return []metrics.Metric{
		{
			ID:    metrics.IDRubySymbolizationSuccess,
			Value: metrics.MetricValue(r.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDRubySymbolizationFailure,
			Value: metrics.MetricValue(r.failCount.Swap(0)),
		},
		{
			ID:    metrics.IDRubyIseqBodyPCHit,
			Value: metrics.MetricValue(rubyIseqBodyPCStats.Hits),
		},
		{
			ID:    metrics.IDRubyIseqBodyPCMiss,
			Value: metrics.MetricValue(rubyIseqBodyPCStats.Misses),
		},
		{
			ID:    metrics.IDRubyIseqBodyPCAdd,
			Value: metrics.MetricValue(rubyIseqBodyPCStats.Inserts),
		},
		{
			ID:    metrics.IDRubyIseqBodyPCDel,
			Value: metrics.MetricValue(rubyIseqBodyPCStats.Removals),
		},
		{
			ID:    metrics.IDRubyAddrToStringHit,
			Value: metrics.MetricValue(addrToStringStats.Hits),
		},
		{
			ID:    metrics.IDRubyAddrToStringMiss,
			Value: metrics.MetricValue(addrToStringStats.Misses),
		},
		{
			ID:    metrics.IDRubyAddrToStringAdd,
			Value: metrics.MetricValue(addrToStringStats.Inserts),
		},
		{
			ID:    metrics.IDRubyAddrToStringDel,
			Value: metrics.MetricValue(addrToStringStats.Removals),
		},
		{
			ID:    metrics.IDRubyMaxSize,
			Value: metrics.MetricValue(r.maxSize.Swap(0)),
		},
	}, nil
}

// determineRubyVersion looks for the symbol ruby_version and extracts version
// information from its value.
func determineRubyVersion(ef *pfelf.File) (uint32, error) {
	_, memory, err := ef.SymbolData("ruby_version", 64)
	if err != nil {
		return 0, fmt.Errorf("unable to read 'ruby_version': %v", err)
	}

	versionString := strings.TrimRight(unsafe.String(unsafe.SliceData(memory), len(memory)), "\x00")
	matches := rubyVersionRegex.FindStringSubmatch(versionString)
	if len(matches) < 3 {
		return 0, fmt.Errorf("failed to parse version string: '%s'", versionString)
	}
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	release, _ := strconv.Atoi(matches[3])

	return rubyVersion(uint32(major), uint32(minor), uint32(release)), nil
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if !rubyRegex.MatchString(info.FileName()) {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	version, err := determineRubyVersion(ef)
	if err != nil {
		return nil, err
	}

	// Reason for lowest supported version:
	// - Ruby 2.5 is still commonly used at time of writing this code.
	//   https://www.jetbrains.com/lp/devecosystem-2020/ruby/
	// Reason for maximum supported version 3.5.x:
	// - this is currently the newest stable version

	minVer, maxVer := rubyVersion(2, 5, 0), rubyVersion(3, 6, 0)
	if version < minVer || version >= maxVer {
		return nil, fmt.Errorf("unsupported Ruby %d.%d.%d (need >= %d.%d.%d and <= %d.%d.%d)",
			(version>>16)&0xff, (version>>8)&0xff, version&0xff,
			(minVer>>16)&0xff, (minVer>>8)&0xff, minVer&0xff,
			(maxVer>>16)&0xff, (maxVer>>8)&0xff, maxVer&0xff)
	}

	log.Debugf("Ruby %d.%d.%d detected", (version>>16)&0xff, (version>>8)&0xff, version&0xff)

	// Before Ruby 2.5 the symbol ruby_current_thread was used for the current execution
	// context but got replaced in [0] with ruby_current_execution_context_ptr.
	// With [1] the Ruby internal execution model changed and the symbol
	// ruby_current_execution_context_ptr was removed. Therefore we need to lookup different
	// symbols depending on the version.
	// [0] https://github.com/ruby/ruby/commit/837fd5e494731d7d44786f29e7d6e8c27029806f
	// [1] https://github.com/ruby/ruby/commit/79df14c04b452411b9d17e26a398e491bca1a811
	currentCtxSymbol := libpf.SymbolName("ruby_single_main_ractor")
	if version < rubyVersion(3, 0, 0) {
		currentCtxSymbol = "ruby_current_execution_context_ptr"
	}

	var currentEcTlsOffset libpf.SymbolValue
	var interpRanges []util.Range

	globalSymbolsName := libpf.SymbolName("ruby_global_symbols")
	if version < rubyVersion(2, 7, 0) {
		globalSymbolsName = libpf.SymbolName("global_symbols")
	}

	// rb_vm_exec is used to execute the Ruby frames in the Ruby VM and is called within
	// ruby_run_node  which is the main executor function since Ruby v1.9.0
	// https://github.com/ruby/ruby/blob/587e6800086764a1b7c959976acef33e230dccc2/main.c#L47
	interpSymbolName := libpf.SymbolName("rb_vm_exec")
	if version < rubyVersion(2, 6, 0) {
		interpSymbolName = libpf.SymbolName("ruby_exec_node")
	}

	var currentEcSymbol *libpf.Symbol
	currentEcSymbolName := libpf.SymbolName("ruby_current_ec")

	log.Infof("Ruby %d.%d.%d detected, looking for currentCtxPtr=%q, currentEcSymbol=%q, globalSymbolsName=%q",
		(version>>16)&0xff, (version>>8)&0xff, version&0xff, currentCtxSymbol, currentEcSymbolName,
		globalSymbolsName)

	currentCtxPtr, err := ef.LookupSymbolAddress(currentCtxSymbol)
	if err != nil {
		log.Debugf("Direct lookup of %v failed: %v, will try fallback", currentCtxSymbol, err)
	}

	globalSymbolsAddr, err := ef.LookupSymbolAddress(globalSymbolsName)
	if err != nil {
		log.Debugf("Direct lookup of %v failed: %v, will try fallback", globalSymbolsName, err)
	}

	interpRanges, err = info.GetSymbolAsRanges(interpSymbolName)
	if err != nil {
		log.Debugf("Direct lookup of %v failed: %v, will try fallback", interpSymbolName, err)
	}

	err = ef.VisitUntilSymbol(func(s libpf.Symbol) bool {
		if s.Name == currentEcSymbolName {
			currentEcSymbol = &s
		}
		if s.Name == globalSymbolsName {
			globalSymbolsAddr = s.Address
		}
		if len(interpRanges) == 0 && s.Name == interpSymbolName {
			interpRanges = info.SymbolAsRanges(&s)
		}
		if len(interpRanges) > 0 && currentEcSymbol != nil && globalSymbolsAddr != libpf.SymbolValueInvalid {
			return false
		}
		return true
	})

	if currentEcSymbol != nil {
		currentEcTlsOffset = currentEcSymbol.Address
	}

	log.Infof("Discovered EC %x, interp ranges: %v, global symbols addr: %v", currentEcTlsOffset, interpRanges, globalSymbolsAddr)

	rid := &rubyData{
		version:            version,
		currentCtxPtr:      libpf.Address(currentCtxPtr),
		currentEcTlsOffset: uint64(currentEcTlsOffset),
		globalSymbolsAddr:  libpf.Address(globalSymbolsAddr),
	}

	vms := &rid.vmStructs

	// Ruby does not provide introspection data, hard code the struct field offsets. Some
	// values can be fairly easily calculated from the struct definitions, but some are
	// looked up by using gdb and getting the field offset directly from debug data.
	vms.execution_context_struct.vm_stack = 0
	vms.execution_context_struct.vm_stack_size = 8
	vms.execution_context_struct.cfp = 16
	vms.execution_context_struct.thread_ptr = 48

	vms.thread_struct.vm = 32 // FIXME this is very ruby version dependent, ractor comes before it

	// Package and sizes varies a lot for this rather large struct between two arches
	if runtime.GOARCH == "amd64" {
		// x86_64:
		//        struct {
		//                struct rb_objspace * objspace;           /*  1296     8 */
		//                struct gc_mark_func_data_struct * mark_func_data; /*  1304     8 */
		//        } gc;
		vms.vm_struct.gc_objspace = 1296 // FIXME this is very ruby version dependent, ractor comes before it
	} else {
		// arm64:
		//        struct {
		//                struct rb_objspace * objspace;           /*  1320     8 */
		//                struct gc_mark_func_data_struct * mark_func_data; /*  1328     8 */
		//        } gc;                                            /*  1320    16 */

		vms.vm_struct.gc_objspace = 1320 // FIXME this is very ruby version dependent, ractor comes before it
	}

	vms.objspace.flags = 20
	vms.objspace.size_of_flags = 4

	vms.control_frame_struct.pc = 0
	vms.control_frame_struct.iseq = 16
	vms.control_frame_struct.ep = 32
	switch {
	case version < rubyVersion(2, 6, 0):
		vms.control_frame_struct.size_of_control_frame_struct = 48
	case version < rubyVersion(3, 1, 0):
		// With Ruby 2.6 the field bp was added to rb_control_frame_t
		// https://github.com/ruby/ruby/commit/ed935aa5be0e5e6b8d53c3e7d76a9ce395dfa18b
		vms.control_frame_struct.size_of_control_frame_struct = 56
	case version < rubyVersion(3, 3, 0):
		// 3.1 adds new jit_return field at the end.
		// https://github.com/ruby/ruby/commit/9d8cc01b758f9385bd4c806f3daff9719e07faa0
		vms.control_frame_struct.size_of_control_frame_struct = 64
	default:
		// 3.3+ bp field was removed
		// https://github.com/ruby/ruby/commit/f302e725e10ae05e613e2c24cae0741f65f2db91
		vms.control_frame_struct.size_of_control_frame_struct = 56
	}
	vms.iseq_struct.body = 16

	vms.iseq_constant_body.iseq_type = 0
	vms.iseq_constant_body.size = 4
	vms.iseq_constant_body.encoded = 8
	vms.iseq_constant_body.location = 64
	switch {
	case version < rubyVersion(2, 6, 0):
		vms.iseq_constant_body.insn_info_body = 112
		vms.iseq_constant_body.insn_info_size = 200
		vms.iseq_constant_body.succ_index_table = 144
		vms.iseq_constant_body.size_of_iseq_constant_body = 288
	case version < rubyVersion(3, 2, 0):
		vms.iseq_constant_body.insn_info_body = 120
		vms.iseq_constant_body.insn_info_size = 136
		vms.iseq_constant_body.succ_index_table = 144
		vms.iseq_constant_body.size_of_iseq_constant_body = 312
	case version < rubyVersion(3, 3, 0):
		vms.iseq_constant_body.insn_info_body = 112
		vms.iseq_constant_body.insn_info_size = 128
		vms.iseq_constant_body.succ_index_table = 136
		vms.iseq_constant_body.size_of_iseq_constant_body = 320
	case version >= rubyVersion(3, 4, 0) && version < rubyVersion(3, 5, 0):
		vms.iseq_constant_body.insn_info_body = 112
		vms.iseq_constant_body.insn_info_size = 128
		vms.iseq_constant_body.succ_index_table = 136
		vms.iseq_constant_body.local_iseq = 168
		vms.iseq_constant_body.size_of_iseq_constant_body = 352
	default: // 3.3.x and 3.5.x have the same values
		vms.iseq_constant_body.insn_info_body = 112
		vms.iseq_constant_body.insn_info_size = 128
		vms.iseq_constant_body.succ_index_table = 136
		vms.iseq_constant_body.local_iseq = 168
		vms.iseq_constant_body.size_of_iseq_constant_body = 344
	}
	vms.iseq_location_struct.pathobj = 0
	vms.iseq_location_struct.base_label = 8
	vms.iseq_location_struct.label = 16

	switch {
	case version < rubyVersion(2, 6, 0):
		vms.iseq_insn_info_entry.position = 0
		vms.iseq_insn_info_entry.size_of_position = 4
		vms.iseq_insn_info_entry.line_no = 4
		vms.iseq_insn_info_entry.size_of_line_no = 4
		vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry = 12
	case version < rubyVersion(3, 1, 0):
		// The position field was removed from this struct with
		// https://github.com/ruby/ruby/commit/295838e6eb1d063c64f7cde5bbbd13c7768908fd
		vms.iseq_insn_info_entry.position = 0
		vms.iseq_insn_info_entry.size_of_position = 0
		vms.iseq_insn_info_entry.line_no = 0
		vms.iseq_insn_info_entry.size_of_line_no = 4
		vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry = 8
	default:
		// https://github.com/ruby/ruby/commit/0a36cab1b53646062026c3181117fad73802baf4
		vms.iseq_insn_info_entry.position = 0
		vms.iseq_insn_info_entry.size_of_position = 0
		vms.iseq_insn_info_entry.line_no = 0
		vms.iseq_insn_info_entry.size_of_line_no = 4
		vms.iseq_insn_info_entry.size_of_iseq_insn_info_entry = 12
	}
	if version < rubyVersion(3, 2, 0) {
		vms.rstring_struct.as_ary = 16
	} else {
		vms.rstring_struct.as_ary = 24
	}
	vms.rstring_struct.as_heap_ptr = 24

	vms.rarray_struct.as_ary = 16
	vms.rarray_struct.as_heap_ptr = 32

	vms.succ_index_table_struct.small_block_ranks = 8
	vms.succ_index_table_struct.block_bits = 16
	vms.succ_index_table_struct.succ_part = 48
	vms.succ_index_table_struct.size_of_succ_dict_block = 80
	vms.size_of_immediate_table = 54

	vms.size_of_value = 8

	if version >= rubyVersion(3, 0, 0) {
		if version >= rubyVersion(3, 3, 0) {
			if runtime.GOARCH == "amd64" {
				vms.rb_ractor_struct.running_ec = 0x180
			} else {
				vms.rb_ractor_struct.running_ec = 0x190
			}

			vms.rb_method_entry_struct.flags = 0
			vms.rb_method_entry_struct.defined_class = 8
			vms.rb_method_entry_struct.def = 16
			vms.rb_method_entry_struct.owner = 32

			vms.rclass_and_rb_classext_t.classext = 32
			vms.rb_classext_struct.as_singleton_class_attached_object = 96
			vms.rb_classext_struct.classpath = 120

			vms.rb_method_definition_struct.method_type = 0
			vms.rb_method_definition_struct.body = 8
			vms.rb_method_definition_struct.original_id = 32
			vms.rb_method_iseq_struct.iseqptr = 0

		} else {
			if runtime.GOARCH == "amd64" {
				vms.rb_ractor_struct.running_ec = 0x208
			} else {
				vms.rb_ractor_struct.running_ec = 0x218
			}
		}
	}

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindRuby, info.FileID(),
		interpRanges); err != nil {
		return nil, err
	}

	return rid, nil
}
