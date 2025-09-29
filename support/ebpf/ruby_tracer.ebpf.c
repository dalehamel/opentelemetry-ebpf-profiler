// This file contains the code and map definitions for the Ruby tracer

#include "ruby_tracer.h"
#include "bpfdefs.h"
#include "tracemgmt.h"
#include "tsd.h"
#include "types.h"

// Map from Ruby process IDs to a structure containing addresses of variables
// we require in order to build the stack trace
bpf_map_def SEC("maps") ruby_procs = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(pid_t),
  .value_size  = sizeof(RubyProcInfo),
  .max_entries = 1024,
};

// The number of Ruby frames to unwind per frame-unwinding eBPF program. If
// we start running out of instructions in the walk_ruby_stack program, one
// option is to adjust this number downwards.
// NOTE the maximum size stack is this times 33
#define FRAMES_PER_WALK_RUBY_STACK 64

#define VM_ENV_FLAG_LOCAL 0x2
#define RUBY_FL_USHIFT    12
#define IMEMO_MASK        0x0f
#define IMEMO_MENT        6

// Record a Ruby cfp frame
static EBPF_INLINE ErrorCode
push_ruby_extra(Trace *trace, u8 frame_type, u64 file, u64 line, u64 iseq_addr)
{
  if (frame_type != ADDR_TYPE_NONE) {
    // Ensure address is actually no more than 48-bits
    u64 addr = file & ADDR_MASK_48_BIT;
    if (addr != file) {
      DEBUG_PRINT("ruby: error pushing extra addr, file data was more than 48 bits");
    } else {
      // Shift data to bits 48-55
      u64 packed = addr | ((u64)frame_type << 48);
      file       = packed;
    }
  }
  // DEBUG_PRINT("%llx", iseq_addr);
  return _push_with_extra(trace, file, line, iseq_addr, FRAME_MARKER_RUBY);
  // return _push(trace, file, line, FRAME_MARKER_RUBY);
}

typedef struct rb_control_frame_struct {
  const void *pc;         // cfp[0]
  void *sp;               // cfp[1]
  const void *iseq;       // cfp[2]
  void *self;             // cfp[3] / block[0]
  const void *ep;         // cfp[4] / block[1]
  const void *block_code; // cfp[5] / block[2] -- iseq, ifunc, or forwarded block handler
  void *jit_return;       // cfp[6] -- return address for JIT code
} rb_control_frame_t;

// #define VM_ENV_DATA_INDEX_ME_CREF    (-2) /* ep[-2] */
// #define VM_ENV_DATA_INDEX_SPECVAL    (-1) /* ep[-1] */
// #define VM_ENV_DATA_INDEX_FLAGS      ( 0) /* ep[ 0] */
typedef struct vm_env_struct {
  const void *me_cref;
  const void *specval;
  const void *flags;
} vm_env_t;

// walk_ruby_stack processes a Ruby VM stack, extracts information from the individual frames and
// pushes this information to user space for symbolization of these frames.
//
// Ruby unwinder workflow:
// From the current execution context struct [0] we can get pointers to the current Ruby VM stack
// as well as to the current call frame pointer (cfp).
// On the Ruby VM stack we have for each cfp one struct [1]. These cfp structs then point to
// instruction sequence (iseq) structs [2] that store the information about file and function name
// that we forward to user space for the symbolization process of the frame, or they may
// point to a callable method entry (cme) [3]. In the Ruby's own backtrace functions, they
// may store either of these [4]. In the case of a cme, since ruby 3.3.0 [5] class names
// have been stored as an easily accessible struct member on the classext, accessible
// through the cme. We will check the frame for IMEMO_MENT to see if it is a cme frame,
// and if so we will try to get the classname. The iseq body is accessible through
// additional indirection of the cme, so we can still get the file and function names
// through the existing method.
//
// If the frame is a cme, we will push it with a separate frame type to userspace
// so that the Symbolizer will know what type of pointer we have given it, and
// can search the struct at the right offsets for the classpath and iseq body.
//
// If the frame is the iseq type, the original logic of just extracting the function
// and file names and line numbers is executed.
//
// [0] rb_execution_context_struct
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L843
//
// [1] rb_control_frame_struct
// https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L760
//
// [3] rb_callable_method_entry_struct
// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/method.h#L63-L69
//
// [4] thread_profile_frames frame storage of cme or iseq
// https://github.com/ruby/ruby/blob/fd59ac6410d0cc93a8baaa42df77491abdb2e9b6/vm_backtrace.c#L1754-L1761
//
// [5] classpath stored as struct member instead of ivar
// https://github.com/ruby/ruby/commit/abff5f62037284024aaf469fc46a6e8de98fa1e3

static EBPF_INLINE ErrorCode walk_ruby_stack(
  PerCPURecord *record,
  const RubyProcInfo *rubyinfo,
  const void *current_ctx_addr,
  int *next_unwinder)
{
  if (!current_ctx_addr) {
    *next_unwinder = get_next_unwinder_after_interpreter();
    return ERR_OK;
  }

  Trace *trace = &record->trace;

  *next_unwinder = PROG_UNWIND_STOP;

  // stack_ptr points to the frame of the Ruby VM call stack that will be unwound next
  void *stack_ptr        = record->rubyUnwindState.stack_ptr;
  // last_stack_frame points to the last frame on the Ruby VM stack we want to process
  void *last_stack_frame = record->rubyUnwindState.last_stack_frame;

  if (!stack_ptr || !last_stack_frame) {
    // stack_ptr_current points to the current frame in the Ruby VM call stack
    void *stack_ptr_current;
    // stack_size does not reflect the number of frames on the Ruby VM stack
    // but contains the current stack size in words.
    // stack_size = size in word (size in bytes / sizeof(VALUE))
    // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L846
    size_t stack_size;

    if (bpf_probe_read_user(
          &stack_ptr_current,
          sizeof(stack_ptr_current),
          (void *)(current_ctx_addr + rubyinfo->vm_stack))) {
      DEBUG_PRINT("ruby: failed to read current stack pointer");
      increment_metric(metricID_UnwindRubyErrReadStackPtr);
      return ERR_RUBY_READ_STACK_PTR;
    }

    if (bpf_probe_read_user(
          &stack_size, sizeof(stack_size), (void *)(current_ctx_addr + rubyinfo->vm_stack_size))) {
      DEBUG_PRINT("ruby: failed to get stack size");
      increment_metric(metricID_UnwindRubyErrReadStackSize);
      return ERR_RUBY_READ_STACK_SIZE;
    }

    // Calculate the base of the stack so we can calculate the number of frames from it.
    // Ruby places two dummy frames on the Ruby VM stack in which we are not interested.
    // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_backtrace.c#L477-L485
    last_stack_frame = stack_ptr_current + (rubyinfo->size_of_value * stack_size) -
                       (2 * rubyinfo->size_of_control_frame_struct);

    if (bpf_probe_read_user(
          &stack_ptr, sizeof(stack_ptr), (void *)(current_ctx_addr + rubyinfo->cfp))) {
      DEBUG_PRINT("ruby: failed to get cfp");
      increment_metric(metricID_UnwindRubyErrReadCfp);
      return ERR_RUBY_READ_CFP;
    }
  }

  u64 frame_addr;
  u8 frame_type;
  // iseq_addr holds the address to a rb_iseq_struct struct
  u64 iseq_addr;
  // iseq_body points to a rb_iseq_constant_body struct
  // void *iseq_body;
  // pc stores the Ruby VM program counter information
  u64 pc;
  // iseq_encoded holds the instruction address and operands of a particular instruction sequence
  // The format of this element is documented in:
  // https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm_core.h#L328-L348
  // u64 iseq_encoded;
  //// iseq_size holds the size in bytes of a particular instruction sequence
  // u32 iseq_size;
  // s64 n;

  rb_control_frame_t control_frame;
  vm_env_t vm_env;

  // If we entered native unwinding because we saw a cfunc frame, lets push that
  // frame now so it can take "ownership" of the native code that was unwound
  if (record->rubyUnwindState.cfunc_saved_frame != 0) {
    ErrorCode error = push_ruby_extra(
      trace,
      record->rubyUnwindState.cfunc_saved_frame_type,
      record->rubyUnwindState.cfunc_saved_frame,
      0,
      0);
    if (error) {
      DEBUG_PRINT("ruby: failed to push cframe");
      return error;
    }
    record->rubyUnwindState.cfunc_saved_frame = 0;
  }

  if (record->rubyUnwindState.last_pushed_frame == stack_ptr) {
    DEBUG_PRINT("ruby: already pushed ruby frame at 0x%llx, skipping", (u64)stack_ptr);
    stack_ptr += rubyinfo->size_of_control_frame_struct;
  }

  // should be at offset 0 on the struct, and size of VALUE, so u64 should fit it
  u64 rbasic_flags = 0;

  UNROLL for (u32 i = 0; i < FRAMES_PER_WALK_RUBY_STACK; ++i)
  {
    pc        = 0;
    iseq_addr = 0;

    // TODO guards here
    bpf_probe_read_user(&control_frame, sizeof(rb_control_frame_t), (void *)(stack_ptr));

    if (bpf_probe_read_user(
          &vm_env, sizeof(vm_env), (void *)(control_frame.ep - sizeof(vm_env) + sizeof(void *)))) {
      DEBUG_PRINT("ruby: failed to get vm env");
      increment_metric(metricID_UnwindRubyErrReadEp);
      return ERR_RUBY_READ_EP;
    }

    // TODO maybe unroll this
    if (!((u64)vm_env.flags & VM_ENV_FLAG_LOCAL)) {
      if (bpf_probe_read_user(
            &vm_env,
            sizeof(vm_env),
            (void *)(control_frame.ep - sizeof(vm_env) + sizeof(void *)))) {
        DEBUG_PRINT("ruby: failed to get vm env");
        increment_metric(metricID_UnwindRubyErrReadEp);
        return ERR_RUBY_READ_EP;
      }
    }

    frame_addr = (u64)vm_env.specval;
    frame_type = ADDR_TYPE_EP;

    if ((u64)vm_env.flags & VM_ENV_FLAG_LOCAL) {
      DEBUG_PRINT("ruby: checking %llx", (u64)vm_env.me_cref);
      if (bpf_probe_read_user(&rbasic_flags, sizeof(rbasic_flags), (void *)(vm_env.me_cref))) {
        DEBUG_PRINT("ruby: failed to read flags to check method entry %llx", (u64)vm_env.me_cref);
        return -1;
      }

      if (((rbasic_flags >> RUBY_FL_USHIFT) & IMEMO_MASK) == IMEMO_MENT) {
        DEBUG_PRINT("ruby: imemo type is method entry");
        frame_addr = (u64)vm_env.me_cref;
        frame_type = ADDR_TYPE_CME;
      }
    }

    iseq_addr = (u64)control_frame.iseq;
    pc        = (u64)control_frame.pc;
    // bpf_probe_read_user(&iseq_addr, sizeof(iseq_addr), (void *)(stack_ptr + rubyinfo->iseq));
    // bpf_probe_read_user(&pc, sizeof(pc), (void *)(stack_ptr + rubyinfo->pc));
    //  If iseq or pc is 0, then this frame represents a registered hook.
    //  https://github.com/ruby/ruby/blob/5445e0435260b449decf2ac16f9d09bae3cafe72/vm.c#L1960
    if (pc == 0 || iseq_addr == 0) {
      // Ruby frames without a PC or iseq are special frames and do not hold information
      // we can use further on. So we either skip them or ask the native unwinder to continue.

      if (rubyinfo->version < 0x20600) {
        // With Ruby version 2.6 the scope of our entry symbol ruby_current_execution_context_ptr
        // got extended. We need this extension to jump back unwinding Ruby VM frames if we
        // continue at this point with unwinding native frames.
        // As this is not available for Ruby versions < 2.6 we just skip this indicator frame and
        // continue unwinding Ruby VM frames. Due to this issue, the ordering of Ruby and native
        // frames might not be correct for Ruby versions < 2.6.
        goto skip;
      }

      //// TODO see if we can drop this check and just push these
      // if (
      //   (ep & (RUBY_FRAME_FLAG_LAMBDA | RUBY_FRAME_FLAG_BMETHOD)) ==
      //   (RUBY_FRAME_FLAG_LAMBDA | RUBY_FRAME_FLAG_BMETHOD)) {
      //   // When identifying Ruby lambda blocks at this point, we do not want to return to the
      //   // native unwinder. So we just skip this Ruby VM frame.
      //   goto skip;
      // }

      // We save this cfp on in the "Record" entry, and when we start the unwinder
      // again we'll push it so that the order is correct and the cfunc "owns" any native code we
      // unwound
      record->rubyUnwindState.cfunc_saved_frame      = frame_addr;
      record->rubyUnwindState.cfunc_saved_frame_type = frame_type;

      // Advance the ruby stack pointer so we will start at the next frame
      stack_ptr += rubyinfo->size_of_control_frame_struct;
      *next_unwinder = PROG_UNWIND_NATIVE;
      goto save_state;
    }

    // For symbolization of the frame we forward the information about the instruction sequence
    // and program counter to user space.
    // From this we can then extract information like file or function name and line number.
    ErrorCode error = push_ruby_extra(trace, frame_type, frame_addr, pc, iseq_addr);
    if (error) {
      DEBUG_PRINT("ruby: failed to push frame");
      return error;
    }
    DEBUG_PRINT("ruby: pushed a ruby frame (%d) at 0x%llx", frame_type, frame_addr);
    record->rubyUnwindState.last_pushed_frame = stack_ptr;
    increment_metric(metricID_UnwindRubyFrames);

  skip:
    if (last_stack_frame <= stack_ptr) {
      DEBUG_PRINT("ruby: bottomed out the stack at 0x%llx", (u64)stack_ptr);
      // We have processed all frames in the Ruby VM and can stop here.
      *next_unwinder = PROG_UNWIND_NATIVE;
      goto save_state;
    }
    stack_ptr += rubyinfo->size_of_control_frame_struct;
  }
  *next_unwinder = PROG_UNWIND_RUBY;

save_state:
  // Store the current progress in the Ruby unwind state so we can continue walking the stack
  // after the tail call.
  record->rubyUnwindState.stack_ptr        = stack_ptr;
  record->rubyUnwindState.last_stack_frame = last_stack_frame;

  return ERR_OK;
}

static EBPF_INLINE u64 addr_for_tls_symbol(u64 symbol, bool dtv, u32 module_id, u32 dtv_step)
{
  u64 tsd_base;
  if (tsd_get_base((void **)&tsd_base) != 0) {
    DEBUG_PRINT("ruby: failed to get TSD base for TLS symbol lookup");
    return 0;
  }

  int err;
  u64 addr;

  if (dtv) {
    u64 dtv_addr;
#if defined(__x86_64__)
    // On x86-64, the FS register points to the TCB
    // The DTV is typically at offset 0 or 8 from the TCB
    // You may need to adjust this offset based on your glibc version

    // Try offset 8 first (common in modern glibc)
    // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/x86_64/nptl/tls.h;h=683f8bfdfcad45734c4cc1aeea844582a5528640;hb=HEAD#l46
    if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *), (void *)(tsd_base + 8)))) {
      // If that fails, try offset 0
      if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *), (void *)tsd_base))) {
        DEBUG_PRINT("ruby: failed to read TLS DTV addr: %d", err);
        return 0;
      }
    }
#elif defined(__aarch64__)
    // on aarch64, it is just at tsdbase
    // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/aarch64/nptl/tls.h;h=ede7c0ddc46fb82fa92d7abac2d5b208eeafb7d4;hb=HEAD#l45
    if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *), (void *)(tsd_base)))) {
      DEBUG_PRINT("ruby: failed to read TLS DTV addr: %d", err);
      return 0;
    }
#endif

    // DTV layout is the same across architectures:
    // DTV[0] = generation counter
    // DTV[1] = module 1's TLS block
    // DTV[2] = module 2's TLS block
    // ...
    u64 dtv_offset = module_id * dtv_step;

    if ((err = bpf_probe_read_user(&addr, sizeof(void *), (void *)(dtv_addr + dtv_offset)))) {
      DEBUG_PRINT(
        "ruby: failed to read TLS block addr for module %d at DTV offset %llu: %d",
        module_id,
        dtv_offset,
        err);
      return 0;
    }
    addr += symbol;
  } else {
    addr = tsd_base + symbol;
  }
  return addr;
}
// unwind_ruby is the tail call destination for PROG_UNWIND_RUBY.
static EBPF_INLINE int unwind_ruby(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  int unwinder           = get_next_unwinder_after_interpreter();
  ErrorCode error        = ERR_OK;
  u32 pid                = record->trace.pid;
  RubyProcInfo *rubyinfo = bpf_map_lookup_elem(&ruby_procs, &pid);
  if (!rubyinfo) {
    DEBUG_PRINT("No Ruby introspection data");
    error = ERR_RUBY_NO_PROC_INFO;
    increment_metric(metricID_UnwindRubyErrNoProcInfo);
    goto exit;
  }

  increment_metric(metricID_UnwindRubyAttempts);

  // Pointer for an address to a rb_execution_context_struct struct.
  void *current_ctx_addr = NULL;

  if (rubyinfo->version >= 0x30004) {
    // With Ruby 3.x and its internal change of the execution model, we can no longer
    // access rb_execution_context_struct directly. We will look up the
    // ruby_current_ec from thread local storage, analogous to how it is done
    // in ruby itself
    // https://github.com/ruby/ruby/blob/6c0315d99a93bdea947f821bd337000420ab41d1/vm_core.h#L2024

    u64 tls_symbol = rubyinfo->current_ec_tls_offset;
    DEBUG_PRINT("ruby: got TLS offset %llu", tls_symbol);
    // assume libruby.so is the first module, which is usually the case.
    // ruby interpreter also only triggers on libruby.so matches, so no need to check for static
    // case.
    u64 tls_current_ec_addr =
      addr_for_tls_symbol(tls_symbol, true, rubyinfo->tls_module_index, rubyinfo->dtv_entry_step);
    DEBUG_PRINT("ruby: got TLS addr 0x%llx", (u64)tls_current_ec_addr);

    if (bpf_probe_read_user(
          &current_ctx_addr, sizeof(current_ctx_addr), (void *)(tls_current_ec_addr))) {
      goto exit;
    }

    DEBUG_PRINT("ruby: EC from TLS: 0x%llx", (u64)current_ctx_addr);
  } else if (rubyinfo->version >= 0x30000) {
    // https://github.com/ruby/ruby/commit/7b3948750e1b1dd8cb271c0a7377b911bb3b8f1b
    // there is no guarantee than an EC exists before 3.0.3
    // ruby versions 3.0.0 - 3.0.3 will use a maybe invalid EC if multiple ractors / threads
    void *single_main_ractor = NULL;
    if (bpf_probe_read_user(
          &single_main_ractor, sizeof(single_main_ractor), (void *)rubyinfo->current_ctx_ptr)) {
      goto exit;
    }

    if (bpf_probe_read_user(
          &current_ctx_addr,
          sizeof(current_ctx_addr),
          (void *)(single_main_ractor + rubyinfo->running_ec))) {
      goto exit;
    }
  } else {
    if (bpf_probe_read_user(
          &current_ctx_addr, sizeof(current_ctx_addr), (void *)rubyinfo->current_ctx_ptr)) {
      goto exit;
    }
  }

  if (!current_ctx_addr) {
    goto exit;
  }

  error = walk_ruby_stack(record, rubyinfo, current_ctx_addr, &unwinder);

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  return -1;
}
MULTI_USE_FUNC(unwind_ruby)
