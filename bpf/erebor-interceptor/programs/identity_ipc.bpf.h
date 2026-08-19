/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_IPC_BPF_H
#define EREBOR_IDENTITY_IPC_BPF_H

/*
 * This relationship gate covers connected AF_UNIX SOCK_STREAM connect,
 * send, and receive. unix_stream_connect supplies both exact sock peers and
 * the accepted child before the effect. socket_accept does not, so it is not
 * used as false peer authority. Datagram, socketpair, SysV IPC, and shared
 * memory attach remain explicit unsupported paths. Pipes use object hooks and
 * are not represented as an exact process pair.
 */
#define IPC_ACTOR_OUTSIDE_PROTECTED_SCOPE 1

static __always_inline struct sock *ipc_socket_sock(struct socket *socket)
{
    return socket ? socket->sk : NULL;
}

static __always_inline bool ipc_is_unix_stream(struct socket *socket)
{
    struct sock *sock = ipc_socket_sock(socket);
    unsigned short family = 0;
    short type = 0;

    if (!sock || BPF_CORE_READ_INTO(&family, sock, __sk_common.skc_family) ||
        BPF_CORE_READ_INTO(&type, socket, type))
        return false;
    return family == AF_UNIX && type == SOCK_STREAM;
}

static __always_inline execution_set_binding_state_v1 *ipc_current_binding(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct cgroup *cgroup = NULL;
    execution_set_binding_state_v1 *binding;
    int binding_lookup;

    if (task_cgroup(task, &cgroup))
        return NULL;
    binding = binding_for_cgroup(cgroup, &binding_lookup);
    return binding_lookup ? NULL : binding;
}

/*
 * Return zero for one fully resolved protected actor, one for a proved host
 * actor, or the physical denial from the common task-first gate.
 */
static __noinline int socket_current_actor(__u16 effect_family,
                                           __u16 operation, int ret)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch = identity_scratch_record();

    if (scratch) {
        scratch->effect_gate_flags = EFFECT_GATE_DEFER_DECISION_V1;
        scratch->effect_gate_operation_argument = 0;
    }
    if (!ret)
        prepare_effect_identity();
    ret = dispatch_identity_effect_gate(
        NULL, NULL, effect_family, operation, ret);
    if (ret)
        return ret;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    if (!config || !config->enabled || !config->effect_policy_enabled ||
        !scratch || id128_is_zero(&scratch->observation.binding_id))
        return IPC_ACTOR_OUTSIDE_PROTECTED_SCOPE;
    return 0;
}

static __noinline int ipc_current_actor(int ret)
{
    return socket_current_actor(kernel_effect_family_v1_ipc,
                                kernel_effect_operation_v1_ipc_access, ret);
}

static __always_inline void ipc_store_endpoint_a(
    ipc_socket_state_v1 *state, const struct identity_scratch_v1 *scratch,
    const execution_set_binding_state_v1 *binding)
{
    __builtin_memset(state, 0, sizeof(*state));
    state->endpoint_a_process_state_id = scratch->process.process_state_id;
    state->endpoint_a_binding_id = binding->binding_id;
    state->endpoint_a_binding_nonce = binding->binding_nonce;
    state->endpoint_a_execution_set_id = binding->execution_set_id;
    state->endpoint_a_profile_generation_ref_id =
        scratch->process.active_profile_generation_ref_id;
    state->endpoint_a_process_transition_version =
        scratch->process.transition_version;
    state->endpoint_a_root_cgroup_id = binding->root_cgroup_id;
    state->endpoint_a_role_id = scratch->process.active_role_id;
    state->transition_version = 1;
    state->channel_kind = ipc_channel_kind_v1_unix_stream;
    state->state = ipc_socket_state_kind_v1_endpoint;
}

static __always_inline bool ipc_endpoint_a_is_current(
    const ipc_socket_state_v1 *state,
    const struct identity_scratch_v1 *scratch,
    const execution_set_binding_state_v1 *binding)
{
    return id128_equal(&state->endpoint_a_process_state_id,
                       &scratch->process.process_state_id) &&
           id128_equal(&state->endpoint_a_binding_id, &binding->binding_id) &&
           id128_equal(&state->endpoint_a_binding_nonce,
                       &binding->binding_nonce) &&
           id128_equal(&state->endpoint_a_execution_set_id,
                       &binding->execution_set_id) &&
           state->endpoint_a_profile_generation_ref_id ==
               scratch->process.active_profile_generation_ref_id &&
           state->endpoint_a_process_transition_version ==
               scratch->process.transition_version &&
           state->endpoint_a_root_cgroup_id == binding->root_cgroup_id &&
           state->endpoint_a_role_id == scratch->process.active_role_id;
}

static __always_inline bool ipc_endpoint_b_is_current(
    const ipc_socket_state_v1 *state,
    const struct identity_scratch_v1 *scratch,
    const execution_set_binding_state_v1 *binding)
{
    return id128_equal(&state->endpoint_b_process_state_id,
                       &scratch->process.process_state_id) &&
           id128_equal(&state->endpoint_b_binding_id, &binding->binding_id) &&
           id128_equal(&state->endpoint_b_binding_nonce,
                       &binding->binding_nonce) &&
           id128_equal(&state->endpoint_b_execution_set_id,
                       &binding->execution_set_id) &&
           state->endpoint_b_profile_generation_ref_id ==
               scratch->process.active_profile_generation_ref_id &&
           state->endpoint_b_process_transition_version ==
               scratch->process.transition_version &&
           state->endpoint_b_root_cgroup_id == binding->root_cgroup_id &&
           state->endpoint_b_role_id == scratch->process.active_role_id;
}

static __always_inline int ipc_validate_stored_endpoint(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    const id128_v1 *process_state_id, const id128_v1 *binding_id,
    const id128_v1 *binding_nonce, const id128_v1 *execution_set_id,
    __u64 profile_generation_ref_id, __u64 process_transition_version,
    __u64 root_cgroup_id, __u32 role_id)
{
    process_security_state_v1 *process;
    process_state_vector_v1 *vector;
    execution_set_binding_state_v1 *binding;
    entry_security_state_v1 *entry;
    profile_generation_descriptor_v1 *generation;
    __u64 *profile_task_refs;

    process = bpf_map_lookup_elem(&process_states, process_state_id);
    vector = bpf_map_lookup_elem(&process_state_vectors, process_state_id);
    binding = bpf_map_lookup_elem(&execution_set_bindings, &root_cgroup_id);
    if (!process || !vector || !binding ||
        snapshot_process_state(process, &scratch->target_process))
        return -EACCES;
    entry = bpf_map_lookup_elem(&entry_states,
                                &scratch->target_process.entry_instance_id);
    generation = bpf_map_lookup_elem(&profile_generation_descriptors,
                                     &profile_generation_ref_id);
    profile_task_refs = bpf_map_lookup_elem(&profile_generation_task_refs,
                                            &profile_generation_ref_id);
    if (scratch->target_process.state !=
            process_security_state_kind_v1_active ||
        !scratch->target_process.live_thread_refs ||
        !id128_equal(&scratch->target_process.process_state_id,
                     process_state_id) ||
        scratch->target_process.active_role_id != role_id ||
        scratch->target_process.active_profile_generation_ref_id !=
            profile_generation_ref_id ||
        scratch->target_process.transition_version !=
            process_transition_version ||
        scratch->target_process.label_epoch != config->label_epoch ||
        !id128_equal(&scratch->target_process.node_boot_id,
                     &config->node_boot_id) ||
        vector->state != process_state_vector_state_v1_active ||
        vector->process_state_vector_id !=
            scratch->target_process.process_state_vector_id ||
        vector->profile_generation_ref_id != profile_generation_ref_id ||
        vector->label_epoch != config->label_epoch ||
        !id128_equal(&vector->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&binding->binding_id, binding_id) ||
        !id128_equal(&binding->binding_nonce, binding_nonce) ||
        !id128_equal(&binding->execution_set_id, execution_set_id) ||
        binding->root_cgroup_id != root_cgroup_id ||
        binding->lifecycle_state != binding_lifecycle_state_v1_active ||
        !entry || entry->admission_state != entry_admission_state_v1_committed ||
        entry->lifetime_state != entry_lifetime_state_v1_active ||
        !entry->live_task_refs ||
        !generation_allows_existing_holder(generation) ||
        generation->profile_generation_ref_id != profile_generation_ref_id ||
        generation->label_epoch != config->label_epoch ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !id128_equal(&generation->profile_id, &binding->profile_id) ||
        !profile_task_refs || __sync_fetch_and_add(profile_task_refs, 0) == 0)
        return -EACCES;
    return 0;
}

static __always_inline int ipc_validate_endpoint_a(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    const ipc_socket_state_v1 *state)
{
    return ipc_validate_stored_endpoint(
        config, scratch, &state->endpoint_a_process_state_id,
        &state->endpoint_a_binding_id, &state->endpoint_a_binding_nonce,
        &state->endpoint_a_execution_set_id,
        state->endpoint_a_profile_generation_ref_id,
        state->endpoint_a_process_transition_version,
        state->endpoint_a_root_cgroup_id, state->endpoint_a_role_id);
}

static __always_inline int ipc_validate_endpoint_b(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    const ipc_socket_state_v1 *state)
{
    return ipc_validate_stored_endpoint(
        config, scratch, &state->endpoint_b_process_state_id,
        &state->endpoint_b_binding_id, &state->endpoint_b_binding_nonce,
        &state->endpoint_b_execution_set_id,
        state->endpoint_b_profile_generation_ref_id,
        state->endpoint_b_process_transition_version,
        state->endpoint_b_root_cgroup_id, state->endpoint_b_role_id);
}

static __always_inline int ipc_apply_relationship(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    __u32 peer_role_id, ipc_operation_v1 operation)
{
    physical_decision_v1 *decision;
    profile_generation_descriptor_v1 *generation;

    scratch->observation.operation_argument = operation;
    __builtin_memset(&scratch->ipc_relationship_key, 0,
                     sizeof(scratch->ipc_relationship_key));
    scratch->ipc_relationship_key.actor_profile_generation_ref_id =
        scratch->process.active_profile_generation_ref_id;
    scratch->ipc_relationship_key.actor_role_id =
        scratch->process.active_role_id;
    scratch->ipc_relationship_key.peer_role_id = peer_role_id;
    scratch->ipc_relationship_key.channel_kind =
        ipc_channel_kind_v1_unix_stream;
    scratch->ipc_relationship_key.operation = operation;
    decision = bpf_map_lookup_elem(&ipc_relationship_decisions,
                                   &scratch->ipc_relationship_key);
    if (!decision) {
        scratch->ipc_relationship_key.peer_role_id = 0;
        decision = bpf_map_lookup_elem(&ipc_relationship_decisions,
                                       &scratch->ipc_relationship_key);
    }
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->process.active_profile_generation_ref_id);
    if (!generation)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    return apply_effect_decision(config, scratch, generation, decision, true,
                                 false);
}

static __noinline int ipc_unsupported(int ret, int status)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;

    if (status == IPC_ACTOR_OUTSIDE_PROTECTED_SCOPE)
        return ret;
    if (status)
        return status;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    if (!config || !scratch)
        return -EACCES;
    return hard_effect_result(config, scratch,
                              effect_observation_reason_v1_unsupported_object);
}

static __noinline int ipc_connected_effect(struct socket *socket,
                                           ipc_operation_v1 operation,
                                           int ret, int status)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    execution_set_binding_state_v1 *binding;
    ipc_socket_state_v1 *state;
    struct sock *sock;
    __u32 peer_role_id;
    if (status == IPC_ACTOR_OUTSIDE_PROTECTED_SCOPE) {
        sock = ipc_socket_sock(socket);
        state = sock ? bpf_sk_storage_get(&ipc_socket_states, sock, 0, 0)
                     : NULL;
        return state ? -EACCES : ret;
    }
    if (status)
        return status;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    binding = ipc_current_binding();
    if (!config || !scratch || !binding)
        return -EACCES;
    scratch->observation.operation_argument = operation;
    sock = ipc_socket_sock(socket);
    state = sock ? bpf_sk_storage_get(&ipc_socket_states, sock, 0, 0) : NULL;
    if (!state || state->state != ipc_socket_state_kind_v1_connected ||
        state->channel_kind != ipc_channel_kind_v1_unix_stream ||
        id128_is_zero(&state->channel_state_id) ||
        state->endpoint_a_profile_generation_ref_id !=
            state->endpoint_b_profile_generation_ref_id)
        return hard_effect_result(
            config, scratch, effect_observation_reason_v1_unsupported_object);
    if (ipc_endpoint_a_is_current(state, scratch, binding)) {
        if (ipc_validate_endpoint_b(config, scratch, state))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        peer_role_id = state->endpoint_b_role_id;
    } else if (ipc_endpoint_b_is_current(state, scratch, binding)) {
        if (ipc_validate_endpoint_a(config, scratch, state))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        peer_role_id = state->endpoint_a_role_id;
    } else {
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    }
    return ipc_apply_relationship(config, scratch, peer_role_id, operation);
}

static __noinline int ipc_socket_post_create_effect(struct socket *socket,
                                                    int ret, int status)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    execution_set_binding_state_v1 *binding;
    ipc_socket_state_v1 *state;
    struct sock *sock;
    if (status == IPC_ACTOR_OUTSIDE_PROTECTED_SCOPE)
        return ret;
    if (status)
        return status;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    binding = ipc_current_binding();
    if (!config || !scratch || !binding)
        return -EACCES;
    sock = ipc_socket_sock(socket);
    state = sock ? bpf_sk_storage_get(
                       &ipc_socket_states, sock, 0,
                       BPF_LOCAL_STORAGE_GET_F_CREATE)
                 : NULL;
    if (!state || state->state != ipc_socket_state_kind_v1_unknown)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    ipc_store_endpoint_a(state, scratch, binding);
    return ret;
}

static __noinline int ipc_unix_stream_connect_effect(
    struct sock *sock, struct sock *other, struct sock *newsk)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    execution_set_binding_state_v1 *binding;
    ipc_socket_state_v1 *client;
    ipc_socket_state_v1 *listener;
    ipc_socket_state_v1 *accepted;
    id128_v1 channel_id = {};
    int status;

    config = identity_runtime_config();
    scratch = identity_scratch_record();
    binding = ipc_current_binding();
    if (!config || !scratch || !binding)
        return -EACCES;
    scratch->observation.operation_argument = ipc_operation_v1_connect;
    client = bpf_sk_storage_get(&ipc_socket_states, sock, 0, 0);
    listener = bpf_sk_storage_get(&ipc_socket_states, other, 0, 0);
    if (!client || !listener ||
        client->state != ipc_socket_state_kind_v1_endpoint ||
        listener->state != ipc_socket_state_kind_v1_endpoint ||
        client->channel_kind != ipc_channel_kind_v1_unix_stream ||
        listener->channel_kind != ipc_channel_kind_v1_unix_stream ||
        !ipc_endpoint_a_is_current(client, scratch, binding) ||
        listener->endpoint_a_profile_generation_ref_id !=
            scratch->process.active_profile_generation_ref_id ||
        ipc_validate_endpoint_a(config, scratch, listener) ||
        allocate_id(config, &channel_id))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);

    ipc_store_endpoint_a(&scratch->ipc_socket_state, scratch, binding);
    scratch->ipc_socket_state.channel_state_id = channel_id;
    scratch->ipc_socket_state.endpoint_b_process_state_id =
        listener->endpoint_a_process_state_id;
    scratch->ipc_socket_state.endpoint_b_binding_id =
        listener->endpoint_a_binding_id;
    scratch->ipc_socket_state.endpoint_b_binding_nonce =
        listener->endpoint_a_binding_nonce;
    scratch->ipc_socket_state.endpoint_b_execution_set_id =
        listener->endpoint_a_execution_set_id;
    scratch->ipc_socket_state.endpoint_b_profile_generation_ref_id =
        listener->endpoint_a_profile_generation_ref_id;
    scratch->ipc_socket_state.endpoint_b_process_transition_version =
        listener->endpoint_a_process_transition_version;
    scratch->ipc_socket_state.endpoint_b_root_cgroup_id =
        listener->endpoint_a_root_cgroup_id;
    scratch->ipc_socket_state.endpoint_b_role_id =
        listener->endpoint_a_role_id;
    scratch->ipc_socket_state.state = ipc_socket_state_kind_v1_connected;
    accepted = bpf_sk_storage_get(&ipc_socket_states, newsk, 0,
                                  BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!accepted)
        return hard_effect_result(
            config, scratch, effect_observation_reason_v1_unsupported_object);
    status = ipc_apply_relationship(config, scratch,
                                    scratch->ipc_socket_state.endpoint_b_role_id,
                                    ipc_operation_v1_connect);
    if (status)
        return status;
    __builtin_memcpy(accepted, &scratch->ipc_socket_state, sizeof(*accepted));
    __builtin_memcpy(client, &scratch->ipc_socket_state, sizeof(*client));
    return 0;
}

static __noinline int ipc_unix_stream_connect_dispatch(struct sock *sock,
                                                       struct sock *other,
                                                       struct sock *newsk,
                                                       int ret, int status)
{
    ipc_socket_state_v1 *listener;
    if (status == IPC_ACTOR_OUTSIDE_PROTECTED_SCOPE) {
        listener = bpf_sk_storage_get(&ipc_socket_states, other, 0, 0);
        return listener ? -EACCES : ret;
    }
    if (status)
        return status;
    return ipc_unix_stream_connect_effect(sock, other, newsk);
}

#include "identity_network.bpf.h"

SEC("lsm/socket_post_create")
int BPF_PROG(erebor_identity_socket_post_create, struct socket *socket,
             int family, int type, int protocol, int kern, int ret)
{
    int status;

    if (family != AF_UNIX) {
        status = network_current_actor(
            kernel_effect_operation_v1_socket_create, ret);
        return network_socket_post_create_result(
            socket, family, type, protocol, status);
    }
    status = ipc_current_actor(ret);
    if (type != SOCK_STREAM)
        return ipc_unsupported(ret, status);
    return ipc_socket_post_create_effect(socket, ret, status);
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(erebor_identity_unix_stream_connect, struct sock *sock,
             struct sock *other, struct sock *newsk, int ret)
{
    int status = ipc_current_actor(ret);

    return ipc_unix_stream_connect_dispatch(sock, other, newsk, ret, status);
}

SEC("lsm/socket_connect")
int BPF_PROG(erebor_identity_socket_connect, struct socket *socket,
             struct sockaddr *address, int addrlen, int ret)
{
    struct sock *sock = ipc_socket_sock(socket);
    unsigned short family = 0;

    if (!sock || BPF_CORE_READ_INTO(&family, sock, __sk_common.skc_family))
        return ipc_unsupported(ret, ipc_current_actor(ret));
    if (family != AF_UNIX)
        return network_apply_destination(
            socket, address, addrlen,
            kernel_effect_operation_v1_connect |
                NETWORK_REQUEST_RETAIN_FLOW,
            network_current_actor(kernel_effect_operation_v1_connect, ret));
    if (ipc_is_unix_stream(socket))
        return ret;
    return ipc_unsupported(ret, ipc_current_actor(ret));
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(erebor_identity_socket_sendmsg, struct socket *socket,
             struct msghdr *msg, int size, int ret)
{
    struct sock *sock = ipc_socket_sock(socket);
    unsigned short family = 0;

    if (!sock || BPF_CORE_READ_INTO(&family, sock, __sk_common.skc_family))
        return ipc_unsupported(ret, ipc_current_actor(ret));
    if (family != AF_UNIX) {
        struct sockaddr *address = NULL;
        int addrlen = 0;

        if (msg) {
            BPF_CORE_READ_INTO(&address, msg, msg_name);
            BPF_CORE_READ_INTO(&addrlen, msg, msg_namelen);
        }
        return network_apply_destination(
            socket, address, addrlen,
            kernel_effect_operation_v1_send | NETWORK_REQUEST_RETAIN_FLOW |
                (!address ? NETWORK_REQUEST_CONNECTED_PEER : 0),
            network_current_actor(kernel_effect_operation_v1_send, ret));
    }
    if (!ipc_is_unix_stream(socket))
        return ipc_unsupported(ret, ipc_current_actor(ret));
    return ipc_connected_effect(socket, ipc_operation_v1_send, ret,
                                ipc_current_actor(ret));
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(erebor_identity_socket_recvmsg, struct socket *socket,
             struct msghdr *msg, int size, int flags, int ret)
{
    struct sock *sock = ipc_socket_sock(socket);
    unsigned short family = 0;

    if (!sock || BPF_CORE_READ_INTO(&family, sock, __sk_common.skc_family))
        return ipc_unsupported(ret, ipc_current_actor(ret));
    if (family != AF_UNIX)
        return network_apply_destination(
            socket, NULL, 0,
            kernel_effect_operation_v1_receive |
                NETWORK_REQUEST_CONNECTED_PEER,
            network_current_actor(kernel_effect_operation_v1_receive, ret));
    if (!ipc_is_unix_stream(socket))
        return ipc_unsupported(ret, ipc_current_actor(ret));
    return ipc_connected_effect(socket, ipc_operation_v1_receive, ret,
                                ipc_current_actor(ret));
}

SEC("lsm/socket_socketpair")
int BPF_PROG(erebor_identity_socket_socketpair, struct socket *socka,
             struct socket *sockb, int ret)
{
    return ipc_unsupported(ret, ipc_current_actor(ret));
}

SEC("lsm/unix_may_send")
int BPF_PROG(erebor_identity_unix_may_send, struct socket *socket,
             struct socket *other, int ret)
{
    return ipc_unsupported(ret, ipc_current_actor(ret));
}

SEC("lsm/ipc_permission")
int BPF_PROG(erebor_identity_ipc_permission, struct kern_ipc_perm *ipcp,
             short flag, int ret)
{
    return ipc_unsupported(ret, ipc_current_actor(ret));
}

SEC("lsm/shm_shmat")
int BPF_PROG(erebor_identity_shm_shmat, struct kern_ipc_perm *perm,
             char *shmaddr, int shmflg, int ret)
{
    return ipc_unsupported(ret, ipc_current_actor(ret));
}

#endif
