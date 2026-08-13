#include "vmlinux.h"
#include "erebor_interceptor_abi.h"
#include "linux_uapi.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

_Static_assert(sizeof(task_label_candidate_v1) == 8, "task label ABI size");
_Static_assert(sizeof(file_open_target_v1) == 8, "file target ABI size");
_Static_assert(sizeof(file_open_event_v1) == 16, "file event ABI size");
_Static_assert(sizeof(effect_decision_key_v1) == 48, "decision key ABI size");
_Static_assert(__builtin_offsetof(effect_decision_key_v1, composite_atom_id) == 24,
               "decision atom ABI offset");
_Static_assert(sizeof(physical_decision_v1) == 16, "decision value ABI size");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, int);
    __type(value, task_label_candidate_v1);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} task_labels SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, file_open_target_v1);
} file_probe_targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} probe_events SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(qualification_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int ret)
{
    struct task_struct *parent;
    task_label_candidate_v1 *parent_label;
    task_label_candidate_v1 *child_label;

    if (ret != 0)
        return ret;
    parent = bpf_get_current_task_btf();
    parent_label = bpf_task_storage_get(&task_labels, parent, 0, 0);
    if (!parent_label)
        return 0;
    child_label = bpf_task_storage_get(&task_labels, task, 0,
                                       BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!child_label)
        return -EACCES;
    child_label->label = parent_label->label;
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(qualification_file_open, struct file *file, int ret)
{
    __u32 key = 0;
    __u64 inode;
    int decision = 0;
    file_open_target_v1 *target;
    file_open_event_v1 *event;

    if (ret != 0)
        return ret;
    target = bpf_map_lookup_elem(&file_probe_targets, &key);
    if (!target || target->inode == 0)
        return 0;
    inode = BPF_CORE_READ(file, f_inode, i_ino);
    if (inode == target->inode)
        decision = -EACCES;
    event = bpf_ringbuf_reserve(&probe_events, sizeof(*event), 0);
    if (event) {
        event->inode = inode;
        event->result = decision;
        event->reserved = 0;
        bpf_ringbuf_submit(event, 0);
    }
    return decision;
}

#define PRESERVE_ONE(NAME, TYPE, ARG)                                      \
    SEC("lsm/" #NAME)                                                     \
int BPF_PROG(qualification_##NAME, TYPE ARG, int ret)                  \
    {                                                                      \
        return ret;                                                        \
    }

PRESERVE_ONE(bprm_check_security, struct linux_binprm *, bprm)

SEC("lsm/file_permission")
int BPF_PROG(qualification_file_permission, struct file *file, int mask, int ret)
{
    return ret;
}

SEC("lsm/file_receive")
int BPF_PROG(qualification_file_receive, struct file *file, int ret)
{
    return ret;
}

SEC("lsm/file_ioctl")
int BPF_PROG(qualification_file_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret)
{
    return ret;
}

SEC("lsm/mmap_file")
int BPF_PROG(qualification_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    return ret;
}

SEC("lsm/file_mprotect")
int BPF_PROG(qualification_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    return ret;
}

SEC("lsm/socket_post_create")
int BPF_PROG(qualification_socket_post_create, struct socket *socket,
             int family, int type, int protocol, int kern, int ret)
{
    return ret;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(qualification_unix_stream_connect, struct sock *sock,
             struct sock *other, struct sock *newsk, int ret)
{
    return ret;
}

SEC("lsm/ipc_permission")
int BPF_PROG(qualification_ipc_permission, struct kern_ipc_perm *ipcp, short flag,
             int ret)
{
    return ret;
}

SEC("lsm/socket_connect")
int BPF_PROG(qualification_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    return ret;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(qualification_socket_sendmsg, struct socket *sock, struct msghdr *msg,
             int size, int ret)
{
    return ret;
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(qualification_socket_recvmsg, struct socket *socket,
             struct msghdr *msg, int size, int flags, int ret)
{
    return ret;
}

SEC("lsm/socket_socketpair")
int BPF_PROG(qualification_socket_socketpair, struct socket *socka,
             struct socket *sockb, int ret)
{
    return ret;
}

SEC("lsm/unix_may_send")
int BPF_PROG(qualification_unix_may_send, struct socket *socket,
             struct socket *other, int ret)
{
    return ret;
}

SEC("lsm/shm_shmat")
int BPF_PROG(qualification_shm_shmat, struct kern_ipc_perm *perm,
             char *shmaddr, int shmflg, int ret)
{
    return ret;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(qualification_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret)
{
    return ret;
}

SEC("lsm/task_kill")
int BPF_PROG(qualification_task_kill, struct task_struct *task,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret)
{
    return ret;
}

SEC("lsm/path_unlink")
int BPF_PROG(qualification_path_unlink, const struct path *dir,
             struct dentry *dentry, int ret)
{
    return ret;
}

SEC("lsm/path_mknod")
int BPF_PROG(qualification_path_mknod, const struct path *dir,
             struct dentry *dentry, umode_t mode, unsigned int device, int ret)
{
    return ret;
}

SEC("lsm/path_mkdir")
int BPF_PROG(qualification_path_mkdir, const struct path *dir,
             struct dentry *dentry, umode_t mode, int ret)
{
    return ret;
}

SEC("lsm/path_symlink")
int BPF_PROG(qualification_path_symlink, const struct path *dir,
             struct dentry *dentry, const char *old_name, int ret)
{
    return ret;
}

SEC("lsm/path_rmdir")
int BPF_PROG(qualification_path_rmdir, const struct path *dir,
             struct dentry *dentry, int ret)
{
    return ret;
}

SEC("lsm/path_chmod")
int BPF_PROG(qualification_path_chmod, const struct path *path, umode_t mode,
             int ret)
{
    return ret;
}

SEC("lsm/path_chown")
int BPF_PROG(qualification_path_chown, const struct path *path,
             unsigned int user, unsigned int group, int ret)
{
    return ret;
}

SEC("lsm/path_truncate")
int BPF_PROG(qualification_path_truncate, const struct path *path, int ret)
{
    return ret;
}

SEC("lsm/file_truncate")
int BPF_PROG(qualification_file_truncate, struct file *file, int ret)
{
    return ret;
}

SEC("lsm/path_link")
int BPF_PROG(qualification_path_link, struct dentry *old_dentry,
             const struct path *dir, struct dentry *new_dentry, int ret)
{
    return ret;
}

SEC("lsm/path_rename")
int BPF_PROG(qualification_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags, int ret)
{
    return ret;
}

SEC("lsm/sb_mount")
int BPF_PROG(qualification_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data, int ret)
{
    return ret;
}

SEC("lsm/sb_umount")
int BPF_PROG(qualification_sb_umount, struct vfsmount *mnt, int flags, int ret)
{
    return ret;
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(qualification_sb_pivotroot, const struct path *old_path,
             const struct path *new_path, int ret)
{
    return ret;
}

SEC("lsm/move_mount")
int BPF_PROG(qualification_move_mount, const struct path *from_path,
             const struct path *to_path, int ret)
{
    return ret;
}

SEC("lsm/capable")
int BPF_PROG(qualification_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts, int ret)
{
    return ret;
}

SEC("lsm/bpf")
int BPF_PROG(qualification_bpf, int cmd, union bpf_attr *attr, unsigned int size,
             int ret)
{
    return ret;
}

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup_skb/egress")
int qualification_final_flow(struct __sk_buff *skb)
{
    return 1;
}
