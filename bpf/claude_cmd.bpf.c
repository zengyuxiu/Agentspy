#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct event_t {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    char source[16];   // "uv_spawn" / "execve"
    char comm[16];     // caller process name
    char file[128];    // command/executable
    char arg0[128];
    char arg1[128];
};
typedef struct event_t event_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct uv_process_options_partial {
    void *exit_cb;
    const char *file;
    const char *const *args;
    const char *const *env;
    const char *cwd;
    unsigned int flags;
};

static __always_inline int is_target_comm(const char comm[16]) {
    // "claude", "bun", "node"
    if (comm[0]=='c'&&comm[1]=='l'&&comm[2]=='a'&&comm[3]=='u'&&comm[4]=='d'&&comm[5]=='e') return 1;
    if (comm[0]=='b'&&comm[1]=='u'&&comm[2]=='n') return 1;
    if (comm[0]=='n'&&comm[1]=='o'&&comm[2]=='d'&&comm[3]=='e') return 1;
    return 0;
}

static __always_inline void fill_common(struct event_t *e, const char *src) {
    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (__u32)id;
    e->tgid = (__u32)(id >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->source, src, 16);
}

SEC("uprobe/uv_spawn")
int uprobe_uv_spawn(struct pt_regs *ctx) {
    struct event_t *e;
    const struct uv_process_options_partial *opt;
    const char *file = 0;
    const char *const *args = 0;
    const char *a0 = 0, *a1 = 0;
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_target_comm(comm)) return 0;

    opt = (const struct uv_process_options_partial *)PT_REGS_PARM3(ctx);
    if (!opt) return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, "uv_spawn");

    bpf_probe_read_user(&file, sizeof(file), &opt->file);
    if (file) bpf_probe_read_user_str(e->file, sizeof(e->file), file);

    bpf_probe_read_user(&args, sizeof(args), &opt->args);
    if (args) {
        bpf_probe_read_user(&a0, sizeof(a0), &args[0]);
        bpf_probe_read_user(&a1, sizeof(a1), &args[1]);
        if (a0) bpf_probe_read_user_str(e->arg0, sizeof(e->arg0), a0);
        if (a1) bpf_probe_read_user_str(e->arg1, sizeof(e->arg1), a1);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kp_execve(struct pt_regs *ctx) {
    struct event_t *e;
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_target_comm(comm)) return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, "execve");

    if (filename) bpf_probe_read_user_str(e->file, sizeof(e->file), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_execveat")
int kp_execveat(struct pt_regs *ctx) {
    struct event_t *e;
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_target_comm(comm)) return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, "execve");

    if (filename) bpf_probe_read_user_str(e->file, sizeof(e->file), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
