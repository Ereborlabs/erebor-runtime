#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "erebor_interceptor_abi_v1.h"

struct task_label_candidate {
    __u64 label;
};

struct file_probe_target {
    __u64 inode;
};

struct file_probe_event {
    __u64 inode;
    __s32 result;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, int);
    __type(value, struct task_label_candidate);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} task_labels SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_probe_target);
} file_probe_targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, EffectDecisionKeyV1);
    __type(value, PhysicalDecisionV1);
} candidate_decisions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} probe_events SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(phase0_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int ret)
{
    struct task_struct *parent;
    struct task_label_candidate *parent_label;
    struct task_label_candidate *child_label;

    if (ret != 0)
        return ret;
    parent = bpf_get_current_task_btf();
    parent_label = bpf_task_storage_get(&task_labels, parent, 0, 0);
    if (!parent_label)
        return 0;
    child_label = bpf_task_storage_get(&task_labels, task, 0,
                                       BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!child_label)
        return -13;
    child_label->label = parent_label->label;
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(phase0_file_open, struct file *file, int ret)
{
    __u32 key = 0;
    __u64 inode;
    int decision = 0;
    struct file_probe_target *target;
    struct file_probe_event *event;

    if (ret != 0)
        return ret;
    target = bpf_map_lookup_elem(&file_probe_targets, &key);
    if (!target || target->inode == 0)
        return 0;
    inode = BPF_CORE_READ(file, f_inode, i_ino);
    if (inode == target->inode)
        decision = -13;
    event = bpf_ringbuf_reserve(&probe_events, sizeof(*event), 0);
    if (event) {
        event->inode = inode;
        event->result = decision;
        bpf_ringbuf_submit(event, 0);
    }
    return decision;
}

#define PRESERVE_ONE(NAME, TYPE, ARG)                                      \
    SEC("lsm/" #NAME)                                                     \
    int BPF_PROG(phase0_##NAME, TYPE ARG, int ret)                         \
    {                                                                      \
        return ret;                                                        \
    }

PRESERVE_ONE(bprm_check_security, struct linux_binprm *, bprm)

SEC("lsm/file_permission")
int BPF_PROG(phase0_file_permission, struct file *file, int mask, int ret)
{
    return ret;
}

SEC("lsm/file_ioctl")
int BPF_PROG(phase0_file_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret)
{
    return ret;
}

SEC("lsm/mmap_file")
int BPF_PROG(phase0_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    return ret;
}

SEC("lsm/file_mprotect")
int BPF_PROG(phase0_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    return ret;
}

SEC("lsm/ipc_permission")
int BPF_PROG(phase0_ipc_permission, struct kern_ipc_perm *ipcp, short flag,
             int ret)
{
    return ret;
}

SEC("lsm/socket_connect")
int BPF_PROG(phase0_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    return ret;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(phase0_socket_sendmsg, struct socket *sock, struct msghdr *msg,
             int size, int ret)
{
    return ret;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(phase0_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret)
{
    return ret;
}

SEC("lsm/task_kill")
int BPF_PROG(phase0_task_kill, struct task_struct *task,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret)
{
    return ret;
}

SEC("lsm/path_unlink")
int BPF_PROG(phase0_path_unlink, const struct path *dir,
             struct dentry *dentry, int ret)
{
    return ret;
}

SEC("lsm/path_link")
int BPF_PROG(phase0_path_link, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry, int ret)
{
    return ret;
}

SEC("lsm/path_rename")
int BPF_PROG(phase0_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags, int ret)
{
    return ret;
}

SEC("lsm/sb_mount")
int BPF_PROG(phase0_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data, int ret)
{
    return ret;
}

SEC("lsm/sb_umount")
int BPF_PROG(phase0_sb_umount, struct vfsmount *mnt, int flags, int ret)
{
    return ret;
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(phase0_sb_pivotroot, const struct path *old_path,
             const struct path *new_path, int ret)
{
    return ret;
}

SEC("lsm/move_mount")
int BPF_PROG(phase0_move_mount, const struct path *from_path,
             const struct path *to_path, int ret)
{
    return ret;
}

SEC("lsm/capable")
int BPF_PROG(phase0_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts, int ret)
{
    return ret;
}

SEC("lsm/bpf")
int BPF_PROG(phase0_bpf, int cmd, union bpf_attr *attr, unsigned int size,
             int ret)
{
    return ret;
}

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup_skb/egress")
int phase0_final_flow(struct __sk_buff *skb)
{
    return 1;
}
