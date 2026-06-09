#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define MAX_RULES 64
#define MAX_ARGV 32
#define MAX_TEXT 4096
#define MAX_STATES 2048

struct deny_rule {
    char token[256];
    char reason[512];
    char rule_id[128];
};

struct pid_state {
    pid_t pid;
    int in_syscall;
    int denied_pending;
};

static struct deny_rule rules[MAX_RULES];
static size_t rule_count;
static struct pid_state states[MAX_STATES];
static unsigned long audit_seq;
static pid_t root_pid;
static int live_traces;

static void die(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "erebor process guard: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    _exit(127);
}

static struct pid_state *state_for(pid_t pid) {
    for (size_t index = 0; index < MAX_STATES; ++index) {
        if (states[index].pid == pid) {
            return &states[index];
        }
    }

    for (size_t index = 0; index < MAX_STATES; ++index) {
        if (states[index].pid == 0) {
            states[index].pid = pid;
            return &states[index];
        }
    }

    return NULL;
}

static void remove_state(pid_t pid) {
    for (size_t index = 0; index < MAX_STATES; ++index) {
        if (states[index].pid == pid) {
            memset(&states[index], 0, sizeof(states[index]));
            return;
        }
    }
}

static void append_text(char *buffer, size_t size, const char *text) {
    size_t used = strlen(buffer);
    if (used >= size - 1) {
        return;
    }
    strncat(buffer, text, size - used - 1);
}

static void json_escape_to_file(FILE *file, const char *value) {
    fputc('"', file);
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; ++cursor) {
        switch (*cursor) {
            case '"':
                fputs("\\\"", file);
                break;
            case '\\':
                fputs("\\\\", file);
                break;
            case '\n':
                fputs("\\n", file);
                break;
            case '\r':
                fputs("\\r", file);
                break;
            case '\t':
                fputs("\\t", file);
                break;
            default:
                if (*cursor < 0x20) {
                    fprintf(file, "\\u%04x", *cursor);
                } else {
                    fputc(*cursor, file);
                }
                break;
        }
    }
    fputc('"', file);
}

static long ptrace_peek(pid_t pid, unsigned long address, int *ok) {
    errno = 0;
    long value = ptrace(PTRACE_PEEKDATA, pid, (void *)address, NULL);
    if (errno != 0) {
        *ok = 0;
        return 0;
    }
    return value;
}

static void read_cstring(pid_t pid, unsigned long address, char *buffer, size_t size) {
    buffer[0] = '\0';
    if (address == 0 || size == 0) {
        return;
    }

    size_t offset = 0;
    while (offset + 1 < size) {
        int ok = 1;
        long word = ptrace_peek(pid, address + offset, &ok);
        if (!ok) {
            return;
        }

        for (size_t byte = 0; byte < sizeof(long) && offset + 1 < size; ++byte) {
            char character = (char)((unsigned long)word >> (byte * 8));
            buffer[offset++] = character;
            if (character == '\0') {
                return;
            }
        }
    }
    buffer[size - 1] = '\0';
}

static unsigned long read_pointer(pid_t pid, unsigned long address, int *ok) {
    long value = ptrace_peek(pid, address, ok);
    return (unsigned long)value;
}

static void read_argv(pid_t pid, unsigned long argv_address, char argv[MAX_ARGV][256], int *argc) {
    *argc = 0;
    if (argv_address == 0) {
        return;
    }

    for (int index = 0; index < MAX_ARGV; ++index) {
        int ok = 1;
        unsigned long pointer = read_pointer(pid, argv_address + (unsigned long)index * sizeof(unsigned long), &ok);
        if (!ok || pointer == 0) {
            return;
        }
        read_cstring(pid, pointer, argv[index], 256);
        if (argv[index][0] == '\0') {
            return;
        }
        *argc += 1;
    }
}

static void command_text(const char *path, char argv[MAX_ARGV][256], int argc, char *buffer, size_t size) {
    buffer[0] = '\0';
    append_text(buffer, size, path);
    for (int index = 0; index < argc; ++index) {
        if (buffer[0] != '\0') {
            append_text(buffer, size, " ");
        }
        append_text(buffer, size, argv[index]);
    }
}

static void parse_rules(void) {
    const char *source = getenv("EREBOR_GUARD_DENY_RULES");
    if (source == NULL || source[0] == '\0') {
        return;
    }

    char *copy = strdup(source);
    if (copy == NULL) {
        die("failed to allocate policy rules");
    }

    char *line_save = NULL;
    char *line = strtok_r(copy, "\n", &line_save);
    while (line != NULL && rule_count < MAX_RULES) {
        char *field_save = NULL;
        char *token = strtok_r(line, "\t", &field_save);
        char *reason = strtok_r(NULL, "\t", &field_save);
        char *rule_id = strtok_r(NULL, "\t", &field_save);

        if (token != NULL && token[0] != '\0') {
            snprintf(rules[rule_count].token, sizeof(rules[rule_count].token), "%s", token);
            snprintf(
                rules[rule_count].reason,
                sizeof(rules[rule_count].reason),
                "%s",
                reason != NULL ? reason : "process execution denied by Erebor policy"
            );
            snprintf(
                rules[rule_count].rule_id,
                sizeof(rules[rule_count].rule_id),
                "%s",
                rule_id != NULL ? rule_id : "erebor-process-guard"
            );
            rule_count += 1;
        }

        line = strtok_r(NULL, "\n", &line_save);
    }

    free(copy);
}

static const struct deny_rule *matching_rule(const char *text) {
    for (size_t index = 0; index < rule_count; ++index) {
        if (strstr(text, rules[index].token) != NULL) {
            return &rules[index];
        }
    }
    return NULL;
}

static void write_audit(
    pid_t pid,
    const char *path,
    char argv[MAX_ARGV][256],
    int argc,
    const char *text,
    const struct deny_rule *rule
) {
    const char *audit_path = getenv("EREBOR_GUARD_AUDIT_JSONL");
    if (audit_path == NULL || audit_path[0] == '\0') {
        return;
    }

    FILE *file = fopen(audit_path, "a");
    if (file == NULL) {
        fprintf(stderr, "erebor process guard: failed to open audit log %s: %s\n", audit_path, strerror(errno));
        return;
    }

    const char *session_id = getenv("EREBOR_SESSION_ID");
    const char *actor_id = getenv("EREBOR_ACTOR_ID");
    const char *tty = getenv("EREBOR_TERMINAL_TTY");
    if (session_id == NULL) {
        session_id = "unknown-session";
    }
    if (actor_id == NULL) {
        actor_id = "agent";
    }
    if (tty == NULL) {
        tty = "false";
    }

    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(cwd, sizeof(cwd), "<unknown>");
    }

    char event_id[256];
    snprintf(event_id, sizeof(event_id), "%s-process-exec-%ld-%lu", session_id, (long)pid, ++audit_seq);
    const char *decision = rule == NULL ? "allow" : "deny";
    const char *risk = rule == NULL ? "medium" : "high";
    const char *reason = rule == NULL ? "agent-issued process execution attempt" : rule->reason;
    const char *rule_id = rule == NULL ? "" : rule->rule_id;

    fprintf(file, "{\"event\":{\"id\":");
    json_escape_to_file(file, event_id);
    fprintf(file, ",\"session_id\":");
    json_escape_to_file(file, session_id);
    fprintf(file, ",\"actor\":{\"id\":");
    json_escape_to_file(file, actor_id);
    fprintf(file, ",\"kind\":\"agent\"},\"surface\":\"terminal\",\"action\":\"process_exec\",\"target\":{\"label\":");
    json_escape_to_file(file, path);
    fprintf(file, ",\"uri\":null},\"payload\":{\"kind\":\"agent_process_exec_attempt\",\"terminal\":{\"surface\":\"terminal\",\"tty\":%s,\"mediation_path\":\"platform_guard\"},\"working_directory\":", strcmp(tty, "true") == 0 ? "true" : "false");
    json_escape_to_file(file, cwd);
    fprintf(file, ",\"parent_process\":\"ptrace-process-guard\",\"argv_summary\":");
    json_escape_to_file(file, text);
    fprintf(file, ",\"command\":[");
    for (int index = 0; index < argc; ++index) {
        if (index > 0) {
            fputc(',', file);
        }
        json_escape_to_file(file, argv[index]);
    }
    fprintf(file, "]},\"risk\":{\"level\":\"%s\",\"reasons\":[", risk);
    json_escape_to_file(file, reason);
    fprintf(file, "]},\"timestamp\":\"unix:%ld\"},\"policy_decision\":{\"type\":\"%s\"", (long)time(NULL), decision);
    if (rule != NULL) {
        fprintf(file, ",\"reason\":");
        json_escape_to_file(file, rule->reason);
        fprintf(file, ",\"rule_id\":");
        json_escape_to_file(file, rule_id);
    }
    fprintf(file, "},\"final_decision\":{\"type\":\"%s\"", decision);
    if (rule != NULL) {
        fprintf(file, ",\"reason\":");
        json_escape_to_file(file, rule->reason);
        fprintf(file, ",\"rule_id\":");
        json_escape_to_file(file, rule_id);
    }
    fprintf(file, "}}\n");
    fclose(file);
}

static int should_deny_exec(pid_t pid, struct user_regs_struct *regs, int is_execveat) {
    char path[512];
    char argv[MAX_ARGV][256];
    int argc = 0;
    unsigned long path_address = is_execveat ? regs->rsi : regs->rdi;
    unsigned long argv_address = is_execveat ? regs->rdx : regs->rsi;

    read_cstring(pid, path_address, path, sizeof(path));
    read_argv(pid, argv_address, argv, &argc);

    char text[MAX_TEXT];
    command_text(path, argv, argc, text, sizeof(text));
    const struct deny_rule *rule = matching_rule(text);
    write_audit(pid, path, argv, argc, text, rule);

    if (rule != NULL) {
        fprintf(stderr, "erebor process guard: denied exec: %s: %s\n", text, rule->reason);
        return 1;
    }

    return 0;
}

static void set_trace_options(pid_t pid) {
    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)options) != 0) {
        die("failed to set ptrace options for pid %ld: %s", (long)pid, strerror(errno));
    }
}

static void continue_trace(pid_t pid, int signal_to_deliver) {
    if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)signal_to_deliver) != 0) {
        if (errno != ESRCH) {
            fprintf(stderr, "erebor process guard: failed to continue pid %ld: %s\n", (long)pid, strerror(errno));
        }
    }
}

static int trace_loop(void) {
    int root_status = 1;

    while (live_traces > 0) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("waitpid failed: %s", strerror(errno));
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == root_pid) {
                if (WIFEXITED(status)) {
                    root_status = WEXITSTATUS(status);
                } else {
                    root_status = 128 + WTERMSIG(status);
                }
            }
            remove_state(pid);
            live_traces -= 1;
            continue;
        }

        if (!WIFSTOPPED(status)) {
            continue_trace(pid, 0);
            continue;
        }

        int stop_signal = WSTOPSIG(status);
        unsigned int event = (unsigned int)status >> 16;

        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
            unsigned long new_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid) == 0 && new_pid != 0) {
                state_for((pid_t)new_pid);
                live_traces += 1;
            }
            continue_trace(pid, 0);
            continue;
        }

        if (event == PTRACE_EVENT_EXEC || event == PTRACE_EVENT_EXIT || event == PTRACE_EVENT_STOP) {
            continue_trace(pid, 0);
            continue;
        }

        if (stop_signal == (SIGTRAP | 0x80)) {
            struct pid_state *state = state_for(pid);
            if (state == NULL) {
                continue_trace(pid, 0);
                continue;
            }

            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
                continue_trace(pid, 0);
                continue;
            }

            if (!state->in_syscall) {
                state->in_syscall = 1;
                if (regs.orig_rax == SYS_execve || regs.orig_rax == SYS_execveat) {
                    int deny = should_deny_exec(pid, &regs, regs.orig_rax == SYS_execveat);
                    if (deny) {
                        regs.orig_rax = (unsigned long)-1;
                        regs.rax = (unsigned long)-EPERM;
                        state->denied_pending = 1;
                        (void)ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    }
                }
            } else {
                if (state->denied_pending) {
                    regs.rax = (unsigned long)-EPERM;
                    state->denied_pending = 0;
                    (void)ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                }
                state->in_syscall = 0;
            }

            continue_trace(pid, 0);
            continue;
        }

        if (stop_signal == SIGSTOP || stop_signal == SIGTRAP) {
            continue_trace(pid, 0);
        } else {
            continue_trace(pid, stop_signal);
        }
    }

    return root_status;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        die("missing session command");
    }

    parse_rules();

    pid_t child = fork();
    if (child < 0) {
        die("fork failed: %s", strerror(errno));
    }

    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            die("PTRACE_TRACEME failed: %s", strerror(errno));
        }
        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);
        fprintf(stderr, "erebor process guard: failed to exec %s: %s\n", argv[1], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }

    root_pid = child;
    live_traces = 1;

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        die("initial waitpid failed: %s", strerror(errno));
    }
    if (!WIFSTOPPED(status)) {
        die("child did not stop for tracing");
    }

    state_for(child);
    set_trace_options(child);
    continue_trace(child, 0);

    return trace_loop();
}
