#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/fcntl.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct event_t {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    char source[16];   // "file_read" / "file_write" / "file_rw" / "execve"
    char comm[16];     // caller process name
    char file[256];    // file path
    char arg0[128];
    char arg1[128];
    char arg2[256];
};
typedef struct event_t event_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s32 syscall_nr;
    unsigned long args[6];
};

struct open_how_partial {
    __u64 flags;
};

struct trace_event_raw_sys_enter_execve {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s32 syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct trace_event_raw_sys_enter_execveat {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s32 syscall_nr;
    __s32 dfd;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
    __s32 flags;
};

static __always_inline int is_target_comm(const char comm[16]) {
    // "claude", "bun", "node"
    if (comm[0]=='c'&&comm[1]=='l'&&comm[2]=='a'&&comm[3]=='u'&&comm[4]=='d'&&comm[5]=='e') return 1;
    if (comm[0]=='b'&&comm[1]=='u'&&comm[2]=='n') return 1;
    if (comm[0]=='n'&&comm[1]=='o'&&comm[2]=='d'&&comm[3]=='e') return 1;
    return 0;
}

static __always_inline void fill_exec_args(struct event_t *e, const char *const *argv) {
    const char *a0 = 0, *a1 = 0, *a2 = 0;
    if (!argv) return;

    bpf_probe_read_user(&a0, sizeof(a0), &argv[0]);
    bpf_probe_read_user(&a1, sizeof(a1), &argv[1]);
    bpf_probe_read_user(&a2, sizeof(a2), &argv[2]);
    if (a0) bpf_probe_read_user_str(e->arg0, sizeof(e->arg0), a0);
    if (a1) bpf_probe_read_user_str(e->arg1, sizeof(e->arg1), a1);
    if (a2) bpf_probe_read_user_str(e->arg2, sizeof(e->arg2), a2);
}

static __always_inline void fill_common(struct event_t *e, const char *src) {
    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (__u32)id;
    e->tgid = (__u32)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->source, src, 16);
}

static __always_inline void set_source_by_flags(struct event_t *e, __u64 flags) {
    __u64 accmode = flags & O_ACCMODE;
    if ((flags & (O_TRUNC | O_CREAT | O_APPEND)) != 0 || accmode == O_WRONLY) {
        fill_common(e, "file_write");
        return;
    }
    if (accmode == O_RDWR) {
        fill_common(e, "file_rw");
        return;
    }
    fill_common(e, "file_read");
}

static __always_inline int submit_open_event(const char *filename, __u64 flags) {
    struct event_t *e;
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_target_comm(comm)) return 0;
    if (!filename) return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    set_source_by_flags(e, flags);
    bpf_probe_read_user_str(e->file, sizeof(e->file), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    __u64 flags = (__u64)ctx->args[2];
    return submit_open_event(filename, flags);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_openat2(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    const struct open_how_partial *how = (const struct open_how_partial *)ctx->args[2];
    __u64 flags = 0;

    if (how) bpf_probe_read_user(&flags, sizeof(flags), &how->flags);
    return submit_open_event(filename, flags);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    struct event_t *e;
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_target_comm(comm)) return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, "execve");

    if (ctx->filename) bpf_probe_read_user_str(e->file, sizeof(e->file), ctx->filename);
    fill_exec_args(e, ctx->argv);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter_execveat *ctx) {
    struct event_t *e;
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_target_comm(comm)) return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, "execve");

    if (ctx->filename) bpf_probe_read_user_str(e->file, sizeof(e->file), ctx->filename);
    fill_exec_args(e, ctx->argv);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
