/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/* Copyright Erebor Labs and contributors */
#ifndef EREBOR_IDENTITY_NETWORK_BPF_H
#define EREBOR_IDENTITY_NETWORK_BPF_H

#define NETWORK_ACTOR_OUTSIDE_PROTECTED_SCOPE 1
#define NETWORK_IPV4_LOOKUP_PREFIX_BITS 192
#define NETWORK_IPV6_LOOKUP_PREFIX_BITS 288
#define SOCK_DGRAM 2
#define SOCK_TYPE_MASK 0xf
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SOL_SOCKET 1
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_KEEPALIVE 9
#define TCP_NODELAY 1
#define NETWORK_REQUEST_OPERATION_MASK 0xffff
#define NETWORK_REQUEST_CONNECTED_PEER (1U << 16)
#define NETWORK_REQUEST_RETAIN_FLOW (1U << 17)

static __always_inline int network_current_actor(__u16 operation, int ret)
{
    return socket_current_actor(kernel_effect_family_v1_network, operation,
                                ret);
}

static __always_inline network_protocol_v1 network_protocol(int type,
                                                            int protocol)
{
    type &= SOCK_TYPE_MASK;
    if (type == SOCK_STREAM && (!protocol || protocol == IPPROTO_TCP))
        return network_protocol_v1_tcp;
    if (type == SOCK_DGRAM && (!protocol || protocol == IPPROTO_UDP))
        return network_protocol_v1_udp;
    return network_protocol_v1_unknown;
}

static __always_inline network_address_family_v1 network_family(int family)
{
    if (family == AF_INET)
        return network_address_family_v1_ipv4;
    if (family == AF_INET6)
        return network_address_family_v1_ipv6;
    return network_address_family_v1_unknown;
}

static __always_inline bool network_socket_is_inet(struct socket *socket)
{
    struct sock *sock = ipc_socket_sock(socket);
    unsigned short family = 0;

    return sock &&
           !BPF_CORE_READ_INTO(&family, sock, __sk_common.skc_family) &&
           (family == AF_INET || family == AF_INET6);
}

static __always_inline int network_namespace_from_net(
    struct net *net, network_namespace_generation_v1 *namespace)
{
    if (!net || !namespace)
        return -1;
    __builtin_memset(namespace, 0, sizeof(*namespace));
    namespace->network_namespace_address = (__u64)net;
    return BPF_CORE_READ_INTO(&namespace->network_namespace_inode, net,
                              ns.inum);
}

static __always_inline int network_socket_namespace(
    struct sock *sock, network_namespace_generation_v1 *namespace)
{
    struct net *net = NULL;

    if (!sock || BPF_CORE_READ_INTO(&net, sock, __sk_common.skc_net.net))
        return -1;
    return network_namespace_from_net(net, namespace);
}

static __always_inline int network_current_namespace(
    network_namespace_generation_v1 *namespace)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct nsproxy *nsproxy = NULL;
    struct net *net = NULL;

    if (!task || BPF_CORE_READ_INTO(&nsproxy, task, nsproxy) || !nsproxy ||
        BPF_CORE_READ_INTO(&net, nsproxy, net_ns))
        return -1;
    return network_namespace_from_net(net, namespace);
}

static __always_inline bool network_namespace_equal(
    const network_namespace_generation_v1 *left,
    const network_namespace_generation_v1 *right)
{
    return left->network_namespace_address ==
               right->network_namespace_address &&
           left->network_namespace_inode == right->network_namespace_inode &&
           left->network_namespace_address && left->network_namespace_inode;
}

static __always_inline void network_populate_observation(
    struct identity_scratch_v1 *scratch,
    const network_socket_state_v1 *state)
{
    if (!scratch || !state)
        return;
    scratch->observation.network_socket_key_id = state->socket_key_id;
    scratch->observation.network_socket_generation = state->socket_generation;
    scratch->observation.network_flow_generation = state->flow_generation;
    scratch->observation.network_flow_authorization_id =
        state->flow_authorization_id;
    scratch->observation.network_destination_policy_handle =
        state->destination_policy_handle;
    scratch->observation.network_creator_destination_policy_handle =
        state->creator_destination_policy_handle;
    scratch->observation.network_flow_authorizer_profile_generation_ref_id =
        state->flow_authorizer_profile_generation_ref_id;
    scratch->observation.network_parent_socket_key_id =
        state->parent_socket_key_id;
    scratch->observation.network_parent_socket_generation =
        state->parent_socket_generation;
    scratch->observation.network_namespace =
        state->socket_network_namespace;
    scratch->observation.network_creator_profile_generation_ref_id =
        state->creator_profile_generation_ref_id;
    __builtin_memcpy(scratch->observation.network_peer_address,
                     state->peer_address, sizeof(state->peer_address));
    scratch->observation.network_peer_port = state->peer_port;
    scratch->observation.network_address_family = state->address_family;
    scratch->observation.network_protocol = state->protocol;
    scratch->observation.network_socket_state = state->state;
}

static __always_inline int network_unsupported(int ret, int status)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;

    if (status == NETWORK_ACTOR_OUTSIDE_PROTECTED_SCOPE)
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

static __always_inline physical_decision_v1 *network_control_decision(
    struct identity_scratch_v1 *scratch, __u64 profile_generation_ref_id,
    __u32 role_id, __u32 process_state_vector_id, __u16 entry_kind,
    binding_lifecycle_state_v1 lifecycle, __u16 operation)
{
    __builtin_memset(&scratch->effect_default, 0,
                     sizeof(scratch->effect_default));
    scratch->effect_default.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->effect_default.active_role_id = role_id;
    scratch->effect_default.entry_kind = entry_kind;
    scratch->effect_default.effect_family = kernel_effect_family_v1_network;
    scratch->effect_default.operation = operation;
    scratch->effect_default.process_state_vector_id = process_state_vector_id;
    scratch->effect_default.binding_lifecycle_state = lifecycle;
    return bpf_map_lookup_elem(&effect_defaults, &scratch->effect_default);
}

static __always_inline physical_decision_v1 *network_destination_decision(
    struct identity_scratch_v1 *scratch, __u64 profile_generation_ref_id,
    __u64 destination_policy_handle, __u32 role_id,
    __u32 process_state_vector_id, __u16 entry_kind,
    binding_lifecycle_state_v1 lifecycle, __u16 operation,
    network_protocol_v1 protocol)
{
    __builtin_memset(&scratch->network_destination_key, 0,
                     sizeof(scratch->network_destination_key));
    scratch->network_destination_key.profile_generation_ref_id =
        profile_generation_ref_id;
    scratch->network_destination_key.destination_policy_handle =
        destination_policy_handle;
    scratch->network_destination_key.active_role_id = role_id;
    scratch->network_destination_key.process_state_vector_id =
        process_state_vector_id;
    scratch->network_destination_key.entry_kind = entry_kind;
    scratch->network_destination_key.operation = operation;
    scratch->network_destination_key.protocol = protocol;
    scratch->network_destination_key.binding_lifecycle_state = lifecycle;
    return bpf_map_lookup_elem(&network_destination_decisions,
                               &scratch->network_destination_key);
}

static __always_inline bool network_decision_allows(
    const physical_decision_v1 *decision,
    const profile_generation_descriptor_v1 *generation)
{
    if (!decision || !generation)
        return false;
    if (decision->decision == physical_decision_kind_v1_allow ||
        decision->decision == physical_decision_kind_v1_audit_allow)
        return true;
    return decision->decision == physical_decision_kind_v1_deny &&
           generation->mode == policy_generation_mode_v1_observe;
}

static __always_inline int network_apply_decision(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    const profile_generation_descriptor_v1 *generation,
    const physical_decision_v1 *decision)
{
    if (!generation)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    return apply_effect_decision(config, scratch, generation, decision, false,
                                 false);
}

static __always_inline int network_response_result(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    const network_socket_state_v1 *state)
{
    network_response_floor_v1 *floor;

    __builtin_memset(&scratch->network_response_key, 0,
                     sizeof(scratch->network_response_key));
    scratch->network_response_key.profile_generation_ref_id =
        state->creator_profile_generation_ref_id;
    scratch->network_response_key.socket_key_id = state->socket_key_id;
    scratch->network_response_key.socket_generation = state->socket_generation;
    floor = bpf_map_lookup_elem(&network_response_floors,
                                &scratch->network_response_key);
    if (!floor)
        return 0;
    if (!floor->fenced ||
        floor->scope != network_response_scope_v1_whole_socket)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    scratch->observation.network_response_scope = floor->scope;
    return emit_effect_observation(
        scratch, identity_deny(config),
        effect_observation_reason_v1_network_response_fence,
        effect_physical_result_v1_denied_before_effect);
}

static __always_inline int network_validate_socket(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    struct sock *sock, network_socket_state_v1 *state)
{
    profile_generation_descriptor_v1 *generation;
    __u64 *socket_refs;

    if (!sock || !state || state->state != network_socket_state_kind_v1_active ||
        state->socket_key_id != (__u64)sock || !state->socket_generation ||
        !state->creator_profile_generation_ref_id ||
        !state->creator_role_id ||
        state->protocol == network_protocol_v1_unknown ||
        state->address_family == network_address_family_v1_unknown ||
        network_current_namespace(
            &scratch->network_socket_state.socket_network_namespace) ||
        !network_namespace_equal(
            &scratch->network_socket_state.socket_network_namespace,
            &state->socket_network_namespace))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &state->creator_profile_generation_ref_id);
    socket_refs = bpf_map_lookup_elem(
        &profile_generation_socket_refs,
        &state->creator_profile_generation_ref_id);
    if (!generation_allows_existing_holder(generation) ||
        generation->profile_generation_ref_id !=
            state->creator_profile_generation_ref_id ||
        generation->label_epoch != config->label_epoch ||
        !id128_equal(&generation->node_boot_id, &config->node_boot_id) ||
        !socket_refs || __sync_fetch_and_add(socket_refs, 0) == 0)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    network_populate_observation(scratch, state);
    return network_response_result(config, scratch, state);
}

static __always_inline int network_replace_flow_authorizer(
    identity_runtime_config_v1 *config, struct identity_scratch_v1 *scratch,
    network_socket_state_v1 *state, __u64 next_generation)
{
    __u64 previous_generation =
        state->flow_authorizer_profile_generation_ref_id;
    __u64 *next_refs;
    __u64 *previous_refs;

    if (!next_generation)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    if (next_generation != state->creator_profile_generation_ref_id &&
        next_generation != previous_generation) {
        next_refs = bpf_map_lookup_elem(&profile_generation_socket_refs,
                                        &next_generation);
        if (!next_refs || !increment_bounded_counter(next_refs))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
    }
    if (previous_generation &&
        previous_generation != state->creator_profile_generation_ref_id &&
        previous_generation != next_generation) {
        previous_refs = bpf_map_lookup_elem(&profile_generation_socket_refs,
                                            &previous_generation);
        if (!previous_refs || !decrement_nonzero_counter(previous_refs)) {
            if (next_generation != state->creator_profile_generation_ref_id &&
                next_generation != previous_generation) {
                next_refs = bpf_map_lookup_elem(
                    &profile_generation_socket_refs, &next_generation);
                if (next_refs)
                    decrement_nonzero_counter(next_refs);
            }
            state->state =
                network_socket_state_kind_v1_reconciliation_required;
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        }
    }
    state->flow_authorizer_profile_generation_ref_id = next_generation;
    return 0;
}

static __noinline int network_apply_control(
    struct socket *socket, __u16 operation, int ret, int status)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    execution_set_binding_state_v1 *binding;
    network_socket_state_v1 *state;
    profile_generation_descriptor_v1 *current_generation;
    profile_generation_descriptor_v1 *creator_generation;
    physical_decision_v1 *current;
    physical_decision_v1 *creator;
    struct sock *sock;
    int response;

    sock = ipc_socket_sock(socket);
    state = sock ? bpf_sk_storage_get(&network_socket_states, sock, 0, 0)
                 : NULL;
    if (status == NETWORK_ACTOR_OUTSIDE_PROTECTED_SCOPE)
        return state ? -EACCES : ret;
    if (status)
        return status;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    binding = ipc_current_binding();
    if (!config || !scratch || !binding)
        return -EACCES;
    response = network_validate_socket(config, scratch, sock, state);
    if (response)
        return response;
    current_generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->process.active_profile_generation_ref_id);
    creator_generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &state->creator_profile_generation_ref_id);
    current = network_control_decision(
        scratch, scratch->process.active_profile_generation_ref_id,
        scratch->process.active_role_id,
        scratch->process.process_state_vector_id,
        scratch->observation.entry_kind, binding->lifecycle_state, operation);
    creator = network_control_decision(
        scratch, state->creator_profile_generation_ref_id,
        state->creator_role_id, state->creator_process_state_vector_id,
        state->creator_entry_kind, state->creator_binding_lifecycle_state,
        operation);
    if (!network_decision_allows(creator, creator_generation))
        return network_apply_decision(config, scratch, creator_generation,
                                      creator);
    return network_apply_decision(config, scratch, current_generation,
                                  current);
}

static __always_inline int network_read_sockaddr(
    const struct sockaddr *address, int addrlen,
    network_address_family_v1 expected_family, __u8 peer_address[16],
    __u16 *peer_port)
{
    if (!address || !peer_address || !peer_port)
        return -1;
    __builtin_memset(peer_address, 0, 16);
    if (expected_family == network_address_family_v1_ipv4) {
        struct sockaddr_in ipv4 = {};
        if (addrlen < sizeof(ipv4) ||
            bpf_probe_read_kernel(&ipv4, sizeof(ipv4), address) ||
            ipv4.sin_family != AF_INET)
            return -1;
        __builtin_memcpy(peer_address, &ipv4.sin_addr.s_addr, 4);
        *peer_port = bpf_ntohs(ipv4.sin_port);
        return *peer_port ? 0 : -1;
    }
    if (expected_family == network_address_family_v1_ipv6) {
        struct sockaddr_in6 ipv6 = {};
        if (addrlen < sizeof(ipv6) ||
            bpf_probe_read_kernel(&ipv6, sizeof(ipv6), address) ||
            ipv6.sin6_family != AF_INET6)
            return -1;
        __builtin_memcpy(peer_address, &ipv6.sin6_addr, 16);
        *peer_port = bpf_ntohs(ipv6.sin6_port);
        return *peer_port ? 0 : -1;
    }
    return -1;
}

static __always_inline int network_read_connected_peer(
    struct sock *sock, network_address_family_v1 family,
    __u8 peer_address[16], __u16 *peer_port)
{
    __be16 port = 0;
    __be32 ipv4 = 0;
    struct in6_addr ipv6 = {};

    if (!sock || !peer_address || !peer_port ||
        BPF_CORE_READ_INTO(&port, sock, __sk_common.skc_dport))
        return -1;
    *peer_port = bpf_ntohs(port);
    __builtin_memset(peer_address, 0, 16);
    if (!*peer_port)
        return -1;
    if (family == network_address_family_v1_ipv4) {
        if (BPF_CORE_READ_INTO(&ipv4, sock, __sk_common.skc_daddr))
            return -1;
        __builtin_memcpy(peer_address, &ipv4, sizeof(ipv4));
        return 0;
    }
    if (family == network_address_family_v1_ipv6) {
        if (BPF_CORE_READ_INTO(&ipv6, sock, __sk_common.skc_v6_daddr))
            return -1;
        __builtin_memcpy(peer_address, &ipv6, sizeof(ipv6));
        return 0;
    }
    return -1;
}

static __always_inline network_destination_class_v1 *
network_classify_destination(struct identity_scratch_v1 *scratch,
                             __u64 profile_generation_ref_id,
                             network_protocol_v1 protocol,
                             network_address_family_v1 family,
                             const __u8 address[16], __u16 port)
{
    network_destination_class_v1 *destination = NULL;
    bool port_allowed = false;

    if (family == network_address_family_v1_ipv4) {
        __builtin_memset(&scratch->network_ipv4_key, 0,
                         sizeof(scratch->network_ipv4_key));
        scratch->network_ipv4_key.prefix_length =
            NETWORK_IPV4_LOOKUP_PREFIX_BITS;
        scratch->network_ipv4_key.profile_generation_ref_id =
            profile_generation_ref_id;
        scratch->network_ipv4_key.protocol = protocol;
        __builtin_memcpy(scratch->network_ipv4_key.address, address, 4);
        destination = bpf_map_lookup_elem(
            &network_ipv4_destination_classes,
            &scratch->network_ipv4_key);
    } else if (family == network_address_family_v1_ipv6) {
        __builtin_memset(&scratch->network_ipv6_key, 0,
                         sizeof(scratch->network_ipv6_key));
        scratch->network_ipv6_key.prefix_length =
            NETWORK_IPV6_LOOKUP_PREFIX_BITS;
        scratch->network_ipv6_key.profile_generation_ref_id =
            profile_generation_ref_id;
        scratch->network_ipv6_key.protocol = protocol;
        __builtin_memcpy(scratch->network_ipv6_key.address, address, 16);
        destination = bpf_map_lookup_elem(
            &network_ipv6_destination_classes,
            &scratch->network_ipv6_key);
    }
    if (!destination || !destination->destination_policy_handle ||
        !destination->port_range_count ||
        destination->port_range_count > MAX_NETWORK_PORT_RANGES_V1)
        return NULL;
#pragma unroll
    for (int index = 0; index < MAX_NETWORK_PORT_RANGES_V1; index++) {
        if (index < destination->port_range_count &&
            port >= destination->port_ranges[index].first &&
            port <= destination->port_ranges[index].last)
            port_allowed = true;
    }
    return port_allowed ? destination : NULL;
}

static __noinline int network_apply_destination(
    struct socket *socket, const struct sockaddr *address, int addrlen,
    __u32 request, int status)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    execution_set_binding_state_v1 *binding;
    network_socket_state_v1 *state;
    network_destination_class_v1 *current_class;
    network_destination_class_v1 *creator_class;
    profile_generation_descriptor_v1 *current_generation;
    profile_generation_descriptor_v1 *creator_generation;
    physical_decision_v1 *current;
    physical_decision_v1 *creator;
    struct sock *sock = ipc_socket_sock(socket);
    __u8 *peer_address;
    __u16 *peer_port;
    id128_v1 *flow_authorization_id;
    __u16 operation = request & NETWORK_REQUEST_OPERATION_MASK;
    bool connected_peer = request & NETWORK_REQUEST_CONNECTED_PEER;
    bool retain_flow = request & NETWORK_REQUEST_RETAIN_FLOW;
    int response;
    int result;

    state = sock ? bpf_sk_storage_get(&network_socket_states, sock, 0, 0)
                 : NULL;
    if (status == NETWORK_ACTOR_OUTSIDE_PROTECTED_SCOPE)
        return state ? -EACCES : 0;
    if (status)
        return status;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    binding = ipc_current_binding();
    if (!config || !scratch || !binding)
        return -EACCES;
    peer_address = scratch->network_socket_state.peer_address;
    peer_port = &scratch->network_socket_state.peer_port;
    flow_authorization_id =
        &scratch->network_socket_state.flow_authorization_id;
    __builtin_memset(peer_address, 0, 16);
    *peer_port = 0;
    __builtin_memset(flow_authorization_id, 0,
                     sizeof(*flow_authorization_id));
    response = network_validate_socket(config, scratch, sock, state);
    if (response)
        return response;
    if (connected_peer) {
        if (!state->flow_generation || !state->peer_port ||
            id128_is_zero(&state->flow_authorization_id) ||
            !state->flow_authorizer_profile_generation_ref_id ||
            !state->destination_policy_handle ||
            !state->creator_destination_policy_handle)
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_unsupported_object);
        __builtin_memcpy(peer_address, state->peer_address, 16);
        *peer_port = state->peer_port;
    } else if (network_read_sockaddr(address, addrlen,
                                     state->address_family, peer_address,
                                     peer_port)) {
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unresolved_object);
    }
    current_class = network_classify_destination(
        scratch, scratch->process.active_profile_generation_ref_id,
        state->protocol, state->address_family, peer_address, *peer_port);
    creator_class = network_classify_destination(
        scratch, state->creator_profile_generation_ref_id, state->protocol,
        state->address_family, peer_address, *peer_port);
    if (!current_class || !creator_class)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unresolved_object);
    scratch->observation.network_destination_policy_handle =
        current_class->destination_policy_handle;
    scratch->observation.network_peer_port = *peer_port;
    __builtin_memcpy(scratch->observation.network_peer_address, peer_address,
                     16);
    current_generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->process.active_profile_generation_ref_id);
    creator_generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &state->creator_profile_generation_ref_id);
    current = network_destination_decision(
        scratch, scratch->process.active_profile_generation_ref_id,
        current_class->destination_policy_handle,
        scratch->process.active_role_id,
        scratch->process.process_state_vector_id,
        scratch->observation.entry_kind, binding->lifecycle_state, operation,
        state->protocol);
    creator = network_destination_decision(
        scratch, state->creator_profile_generation_ref_id,
        creator_class->destination_policy_handle, state->creator_role_id,
        state->creator_process_state_vector_id, state->creator_entry_kind,
        state->creator_binding_lifecycle_state, operation, state->protocol);
    if (!network_decision_allows(creator, creator_generation))
        return network_apply_decision(config, scratch, creator_generation,
                                      creator);
    result = network_apply_decision(config, scratch, current_generation,
                                    current);
    if (!result && retain_flow) {
        if (allocate_id(config, flow_authorization_id))
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        if (!increment_bounded_counter(&state->flow_generation)) {
            state->state =
                network_socket_state_kind_v1_reconciliation_required;
            return hard_effect_result(
                config, scratch,
                effect_observation_reason_v1_corrupt_identity_or_generation);
        }
        result = network_replace_flow_authorizer(
            config, scratch, state,
            scratch->process.active_profile_generation_ref_id);
        if (result)
            return result;
        state->destination_policy_handle =
            current_class->destination_policy_handle;
        state->creator_destination_policy_handle =
            creator_class->destination_policy_handle;
        state->flow_authorization_id = *flow_authorization_id;
        state->peer_port = *peer_port;
        __builtin_memcpy(state->peer_address, peer_address, 16);
    }
    return result;
}

static __always_inline int network_socket_create_result(
    int family, int type, int protocol, int ret)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    execution_set_binding_state_v1 *binding;
    profile_generation_descriptor_v1 *generation;
    physical_decision_v1 *decision;
    int status = network_current_actor(
        kernel_effect_operation_v1_socket_create, ret);

    if (status == NETWORK_ACTOR_OUTSIDE_PROTECTED_SCOPE)
        return ret;
    if (status)
        return status;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    binding = ipc_current_binding();
    if (!config || !scratch || !binding)
        return -EACCES;
    if (network_family(family) == network_address_family_v1_unknown ||
        network_protocol(type, protocol) == network_protocol_v1_unknown)
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_unsupported_object);
    generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->process.active_profile_generation_ref_id);
    decision = network_control_decision(
        scratch, scratch->process.active_profile_generation_ref_id,
        scratch->process.active_role_id,
        scratch->process.process_state_vector_id,
        scratch->observation.entry_kind, binding->lifecycle_state,
        kernel_effect_operation_v1_socket_create);
    return network_apply_decision(config, scratch, generation, decision);
}

static __noinline int network_socket_post_create_result(
    struct socket *socket, int family, int type, int protocol, int status)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    execution_set_binding_state_v1 *binding;
    network_socket_state_v1 *state;
    struct sock *sock = ipc_socket_sock(socket);
    __u64 *socket_refs;
    id128_v1 socket_generation_id = {};
    if (status == NETWORK_ACTOR_OUTSIDE_PROTECTED_SCOPE)
        return 0;
    if (status)
        return status;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    binding = ipc_current_binding();
    if (!config || !scratch || !binding || !sock)
        return -EACCES;
    state = bpf_sk_storage_get(&network_socket_states, sock, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    socket_refs = bpf_map_lookup_elem(
        &profile_generation_socket_refs,
        &scratch->process.active_profile_generation_ref_id);
    if (!state || state->state != network_socket_state_kind_v1_unknown ||
        !socket_refs || !increment_bounded_counter(socket_refs))
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    __builtin_memset(state, 0, sizeof(*state));
    state->creator_process_state_id = scratch->process.process_state_id;
    state->creator_authority_domain_id =
        scratch->process.authority_domain_id;
    state->creator_binding_id = binding->binding_id;
    state->creator_binding_nonce = binding->binding_nonce;
    state->creator_execution_set_id = binding->execution_set_id;
    state->creator_profile_generation_ref_id =
        scratch->process.active_profile_generation_ref_id;
    state->creator_process_transition_version =
        scratch->process.transition_version;
    state->creator_root_cgroup_id = binding->root_cgroup_id;
    state->socket_key_id = (__u64)sock;
    if (allocate_id(config, &socket_generation_id)) {
        decrement_nonzero_counter(socket_refs);
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    }
    state->socket_generation = socket_generation_id.low;
    if (!state->socket_generation ||
        network_socket_namespace(sock, &state->socket_network_namespace)) {
        decrement_nonzero_counter(socket_refs);
        return hard_effect_result(
            config, scratch,
            effect_observation_reason_v1_corrupt_identity_or_generation);
    }
    state->creator_role_id = scratch->process.active_role_id;
    state->creator_process_state_vector_id =
        scratch->process.process_state_vector_id;
    state->creator_entry_kind = scratch->observation.entry_kind;
    state->creator_binding_lifecycle_state = binding->lifecycle_state;
    state->address_family = network_family(family);
    state->protocol = network_protocol(type, protocol);
    state->socket_type = type & SOCK_TYPE_MASK;
    state->state = network_socket_state_kind_v1_active;
    network_populate_observation(scratch, state);
    return 0;
}

static __always_inline int network_packet_drop(
    struct identity_scratch_v1 *scratch,
    const network_socket_state_v1 *state, __u8 reason,
    const __u8 peer_address[16], __u16 peer_port)
{
    if (!scratch)
        return 0;
    begin_effect_observation(scratch, kernel_effect_family_v1_network,
                             kernel_effect_operation_v1_send);
    if (state) {
        network_populate_observation(scratch, state);
        scratch->observation.profile_generation_ref_id =
            state->flow_authorizer_profile_generation_ref_id;
    }
    if (peer_address)
        __builtin_memcpy(scratch->observation.network_peer_address,
                         peer_address, 16);
    scratch->observation.network_peer_port = peer_port;
    emit_effect_observation(
        scratch, 0, reason,
        effect_physical_result_v1_packet_dropped_after_rewrite);
    return 0;
}

static __always_inline int network_packet_destination(
    struct __sk_buff *skb, network_address_family_v1 *family,
    network_protocol_v1 *protocol, __u8 peer_address[16], __u16 *peer_port)
{
    __u8 first = 0;
    __u8 next_header = 0;
    __u16 fragment = 0;
    __be16 port = 0;
    __u32 transport_offset;

    if (!skb || !family || !protocol || !peer_address || !peer_port ||
        bpf_skb_load_bytes(skb, 0, &first, sizeof(first)))
        return -1;
    __builtin_memset(peer_address, 0, 16);
    if ((first >> 4) == 4) {
        transport_offset = (__u32)(first & 0xf) * 4;
        if (transport_offset < 20 || transport_offset > 60 ||
            bpf_skb_load_bytes(skb, 6, &fragment, sizeof(fragment)) ||
            (bpf_ntohs(fragment) & 0x3fff) ||
            bpf_skb_load_bytes(skb, 9, &next_header,
                               sizeof(next_header)) ||
            bpf_skb_load_bytes(skb, 16, peer_address, 4))
            return -1;
        *family = network_address_family_v1_ipv4;
    } else if ((first >> 4) == 6) {
        transport_offset = 40;
        if (bpf_skb_load_bytes(skb, 6, &next_header,
                               sizeof(next_header)) ||
            bpf_skb_load_bytes(skb, 24, peer_address, 16))
            return -1;
        *family = network_address_family_v1_ipv6;
    } else {
        return -1;
    }
    if (next_header == IPPROTO_TCP)
        *protocol = network_protocol_v1_tcp;
    else if (next_header == IPPROTO_UDP)
        *protocol = network_protocol_v1_udp;
    else
        return -1;
    if (bpf_skb_load_bytes(skb, transport_offset + 2, &port, sizeof(port)))
        return -1;
    *peer_port = bpf_ntohs(port);
    return *peer_port ? 0 : -1;
}

static __always_inline bool network_packet_generation_valid(
    const identity_runtime_config_v1 *config, __u64 generation_ref_id)
{
    profile_generation_descriptor_v1 *generation = bpf_map_lookup_elem(
        &profile_generation_descriptors, &generation_ref_id);
    __u64 *socket_refs = bpf_map_lookup_elem(
        &profile_generation_socket_refs, &generation_ref_id);

    return generation_ref_id && generation_allows_existing_holder(generation) &&
           generation->profile_generation_ref_id == generation_ref_id &&
           generation->label_epoch == config->label_epoch &&
           id128_equal(&generation->node_boot_id, &config->node_boot_id) &&
           socket_refs && __sync_fetch_and_add(socket_refs, 0) > 0;
}

SEC("cgroup_skb/egress")
int erebor_network_final_flow(struct __sk_buff *skb)
{
    identity_runtime_config_v1 *config = identity_runtime_config();
    struct identity_scratch_v1 *scratch = identity_scratch_record();
    struct bpf_sock *full_sock;
    network_socket_state_v1 *state;
    network_destination_class_v1 *destination;
    network_response_floor_v1 *floor;
    execution_set_binding_state_v1 *binding;
    network_address_family_v1 family = network_address_family_v1_unknown;
    network_protocol_v1 protocol = network_protocol_v1_unknown;
    __u8 peer_address[16] = {};
    __u16 peer_port = 0;
    __u64 destination_handle;
    __u64 cgroup_id;

    if (!config || !config->enabled || !config->effect_policy_enabled)
        return 1;
    if (!scratch)
        return 0;
    full_sock = skb && skb->sk ? bpf_sk_fullsock(skb->sk) : NULL;
    state = full_sock
                ? bpf_sk_storage_get(&network_socket_states, full_sock, 0, 0)
                : NULL;
    if (!state) {
        cgroup_id = bpf_skb_cgroup_id(skb);
        binding = bpf_map_lookup_elem(&execution_set_bindings, &cgroup_id);
        return binding ? network_packet_drop(
                             scratch, NULL,
                             effect_observation_reason_v1_missing_identity,
                             NULL, 0)
                       : 1;
    }
    if (state->state != network_socket_state_kind_v1_active ||
        !state->socket_generation || !state->flow_generation ||
        id128_is_zero(&state->flow_authorization_id) ||
        !state->destination_policy_handle ||
        !state->creator_destination_policy_handle ||
        !network_packet_generation_valid(
            config, state->creator_profile_generation_ref_id) ||
        !network_packet_generation_valid(
            config, state->flow_authorizer_profile_generation_ref_id))
        return network_packet_drop(
            scratch, state,
            effect_observation_reason_v1_corrupt_identity_or_generation,
            NULL, 0);
    if (network_packet_destination(skb, &family, &protocol, peer_address,
                                   &peer_port) ||
        family != state->address_family || protocol != state->protocol)
        return network_packet_drop(
            scratch, state,
            effect_observation_reason_v1_unsupported_object, peer_address,
            peer_port);
    __builtin_memset(&scratch->network_response_key, 0,
                     sizeof(scratch->network_response_key));
    scratch->network_response_key.profile_generation_ref_id =
        state->creator_profile_generation_ref_id;
    scratch->network_response_key.socket_key_id = state->socket_key_id;
    scratch->network_response_key.socket_generation = state->socket_generation;
    floor = bpf_map_lookup_elem(&network_response_floors,
                                &scratch->network_response_key);
    if (floor) {
        scratch->observation.network_response_scope = floor->scope;
        return network_packet_drop(
            scratch, state,
            floor->fenced &&
                    floor->scope == network_response_scope_v1_whole_socket
                ? effect_observation_reason_v1_network_response_fence
                : effect_observation_reason_v1_corrupt_identity_or_generation,
            peer_address, peer_port);
    }
    destination = network_classify_destination(
        scratch, state->flow_authorizer_profile_generation_ref_id, protocol,
        family, peer_address, peer_port);
    if (!destination)
        return network_packet_drop(
            scratch, state, effect_observation_reason_v1_unresolved_object,
            peer_address, peer_port);
    destination_handle = destination->destination_policy_handle;
    if (destination_handle != state->destination_policy_handle)
        return network_packet_drop(
            scratch, state, effect_observation_reason_v1_exact_policy_deny,
            peer_address, peer_port);
    destination = network_classify_destination(
        scratch, state->creator_profile_generation_ref_id, protocol, family,
        peer_address, peer_port);
    if (!destination || destination->destination_policy_handle !=
                            state->creator_destination_policy_handle)
        return network_packet_drop(
            scratch, state, effect_observation_reason_v1_exact_policy_deny,
            peer_address, peer_port);
    return 1;
}

SEC("lsm/socket_create")
int BPF_PROG(erebor_identity_socket_create, int family, int type, int protocol,
             int kern, int ret)
{
    if (family != AF_INET && family != AF_INET6)
        return ret;
    return network_socket_create_result(family, type, protocol, ret);
}

SEC("lsm/socket_bind")
int BPF_PROG(erebor_identity_socket_bind, struct socket *socket,
             struct sockaddr *address, int addrlen, int ret)
{
    if (!network_socket_is_inet(socket))
        return ret;
    return network_apply_destination(
        socket, address, addrlen, kernel_effect_operation_v1_bind,
        network_current_actor(kernel_effect_operation_v1_bind, ret));
}

SEC("lsm/socket_listen")
int BPF_PROG(erebor_identity_socket_listen, struct socket *socket, int backlog,
             int ret)
{
    if (!network_socket_is_inet(socket))
        return ret;
    return network_apply_control(
        socket, kernel_effect_operation_v1_listen, ret,
        network_current_actor(kernel_effect_operation_v1_listen, ret));
}

SEC("lsm/socket_accept")
int BPF_PROG(erebor_identity_socket_accept, struct socket *socket,
             struct socket *newsock, int ret)
{
    if (!network_socket_is_inet(socket))
        return ret;
    return network_apply_control(
        socket, kernel_effect_operation_v1_accept, ret,
        network_current_actor(kernel_effect_operation_v1_accept, ret));
}

static __noinline int network_accept_post_result(struct sock *accepted,
                                                 int status)
{
    identity_runtime_config_v1 *config;
    struct identity_scratch_v1 *scratch;
    execution_set_binding_state_v1 *binding;
    network_socket_state_v1 *state;
    network_destination_class_v1 *current_class;
    network_destination_class_v1 *parent_class;
    profile_generation_descriptor_v1 *current_generation;
    profile_generation_descriptor_v1 *parent_generation;
    physical_decision_v1 *current;
    physical_decision_v1 *parent;
    network_namespace_generation_v1 current_namespace = {};
    __u64 *socket_refs;
    __u8 peer_address[16] = {};
    __u16 peer_port = 0;
    id128_v1 socket_generation_id = {};
    id128_v1 flow_authorization_id = {};
    if (!accepted)
        return 0;
    state = bpf_sk_storage_get(&network_socket_states, accepted, 0, 0);
    if (!state || state->state != network_socket_state_kind_v1_active)
        return 0;
    scratch = identity_scratch_record();
    if (!scratch)
        return 0;
    __builtin_memcpy(&scratch->network_socket_state, state, sizeof(*state));
    state->state = network_socket_state_kind_v1_reconciliation_required;
    if (status)
        return 0;
    config = identity_runtime_config();
    scratch = identity_scratch_record();
    binding = ipc_current_binding();
    if (!config || !scratch || !binding ||
        network_current_namespace(&current_namespace) ||
        !network_namespace_equal(
            &current_namespace,
            &scratch->network_socket_state.socket_network_namespace) ||
        network_read_connected_peer(
            accepted, scratch->network_socket_state.address_family,
            peer_address, &peer_port))
        return 0;
    current_class = network_classify_destination(
        scratch, scratch->process.active_profile_generation_ref_id,
        scratch->network_socket_state.protocol,
        scratch->network_socket_state.address_family, peer_address,
        peer_port);
    parent_class = network_classify_destination(
        scratch,
        scratch->network_socket_state.creator_profile_generation_ref_id,
        scratch->network_socket_state.protocol,
        scratch->network_socket_state.address_family, peer_address,
        peer_port);
    if (!current_class || !parent_class)
        return 0;
    current_generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->process.active_profile_generation_ref_id);
    parent_generation = bpf_map_lookup_elem(
        &profile_generation_descriptors,
        &scratch->network_socket_state.creator_profile_generation_ref_id);
    current = network_destination_decision(
        scratch, scratch->process.active_profile_generation_ref_id,
        current_class->destination_policy_handle,
        scratch->process.active_role_id,
        scratch->process.process_state_vector_id,
        scratch->observation.entry_kind, binding->lifecycle_state,
        kernel_effect_operation_v1_accept,
        scratch->network_socket_state.protocol);
    parent = network_destination_decision(
        scratch,
        scratch->network_socket_state.creator_profile_generation_ref_id,
        parent_class->destination_policy_handle,
        scratch->network_socket_state.creator_role_id,
        scratch->network_socket_state.creator_process_state_vector_id,
        scratch->network_socket_state.creator_entry_kind,
        scratch->network_socket_state.creator_binding_lifecycle_state,
        kernel_effect_operation_v1_accept,
        scratch->network_socket_state.protocol);
    if (!network_decision_allows(current, current_generation) ||
        !network_decision_allows(parent, parent_generation))
        return 0;
    socket_refs = bpf_map_lookup_elem(
        &profile_generation_socket_refs,
        &scratch->process.active_profile_generation_ref_id);
    if (!socket_refs || !increment_bounded_counter(socket_refs))
        return 0;
    if (allocate_id(config, &socket_generation_id) ||
        allocate_id(config, &flow_authorization_id)) {
        decrement_nonzero_counter(socket_refs);
        return 0;
    }
    __builtin_memset(state, 0, sizeof(*state));
    state->creator_process_state_id = scratch->process.process_state_id;
    state->creator_authority_domain_id = scratch->process.authority_domain_id;
    state->creator_binding_id = binding->binding_id;
    state->creator_binding_nonce = binding->binding_nonce;
    state->creator_execution_set_id = binding->execution_set_id;
    state->socket_network_namespace = current_namespace;
    state->creator_profile_generation_ref_id =
        scratch->process.active_profile_generation_ref_id;
    state->creator_process_transition_version =
        scratch->process.transition_version;
    state->creator_root_cgroup_id = binding->root_cgroup_id;
    state->socket_key_id = (__u64)accepted;
    state->socket_generation = socket_generation_id.low;
    state->flow_generation = 1;
    state->flow_authorization_id = flow_authorization_id;
    state->destination_policy_handle =
        current_class->destination_policy_handle;
    state->creator_destination_policy_handle =
        current_class->destination_policy_handle;
    state->flow_authorizer_profile_generation_ref_id =
        scratch->process.active_profile_generation_ref_id;
    state->parent_socket_key_id =
        scratch->network_socket_state.socket_key_id;
    state->parent_socket_generation =
        scratch->network_socket_state.socket_generation;
    state->creator_role_id = scratch->process.active_role_id;
    state->creator_process_state_vector_id =
        scratch->process.process_state_vector_id;
    state->creator_entry_kind = scratch->observation.entry_kind;
    state->address_family = scratch->network_socket_state.address_family;
    state->protocol = scratch->network_socket_state.protocol;
    state->socket_type = scratch->network_socket_state.socket_type;
    state->peer_port = peer_port;
    __builtin_memcpy(state->peer_address, peer_address, 16);
    state->creator_binding_lifecycle_state = binding->lifecycle_state;
    state->state = network_socket_state_kind_v1_active;
    return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(erebor_network_inet_csk_accept, struct sock *listener, int flags,
             int *error, bool kern, struct sock *accepted)
{
    (void)listener;
    (void)flags;
    (void)error;
    (void)kern;
    return network_accept_post_result(
        accepted,
        network_current_actor(kernel_effect_operation_v1_accept, 0));
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(erebor_identity_socket_setsockopt, struct socket *socket,
             int level, int optname, int ret)
{
    int status = network_current_actor(
        kernel_effect_operation_v1_setsockopt, ret);

    if (!network_socket_is_inet(socket))
        return ret;
    if (!((level == SOL_SOCKET &&
           (optname == SO_SNDBUF || optname == SO_RCVBUF ||
            optname == SO_KEEPALIVE)) ||
          (level == IPPROTO_TCP && optname == TCP_NODELAY)))
        return network_unsupported(ret, status);
    return network_apply_control(socket, kernel_effect_operation_v1_setsockopt,
                                 ret, status);
}

SEC("lsm/socket_shutdown")
int BPF_PROG(erebor_identity_socket_shutdown, struct socket *socket, int how,
             int ret)
{
    if (!network_socket_is_inet(socket))
        return ret;
    return network_apply_control(
        socket, kernel_effect_operation_v1_shutdown, ret,
        network_current_actor(kernel_effect_operation_v1_shutdown, ret));
}

SEC("fentry/__sock_release")
int BPF_PROG(erebor_network_socket_release, struct socket *socket,
             struct inode *inode)
{
    network_socket_state_v1 *state;
    network_response_floor_key_v1 key = {};
    struct sock *sock = ipc_socket_sock(socket);
    __u64 *socket_refs;
    __u64 *flow_refs;

    if (!sock)
        return 0;
    state = bpf_sk_storage_get(&network_socket_states, sock, 0, 0);
    if (!state ||
        (state->state != network_socket_state_kind_v1_active &&
         state->state != network_socket_state_kind_v1_fenced &&
         state->state !=
             network_socket_state_kind_v1_reconciliation_required))
        return 0;
    socket_refs = bpf_map_lookup_elem(
        &profile_generation_socket_refs,
        &state->creator_profile_generation_ref_id);
    if (socket_refs)
        decrement_nonzero_counter(socket_refs);
    if (state->flow_authorizer_profile_generation_ref_id &&
        state->flow_authorizer_profile_generation_ref_id !=
            state->creator_profile_generation_ref_id) {
        flow_refs = bpf_map_lookup_elem(
            &profile_generation_socket_refs,
            &state->flow_authorizer_profile_generation_ref_id);
        if (flow_refs)
            decrement_nonzero_counter(flow_refs);
    }
    key.profile_generation_ref_id =
        state->creator_profile_generation_ref_id;
    key.socket_key_id = state->socket_key_id;
    key.socket_generation = state->socket_generation;
    bpf_map_delete_elem(&network_response_floors, &key);
    state->state = network_socket_state_kind_v1_tombstoned;
    return 0;
}

#endif
