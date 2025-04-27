#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define NUM_SYSCALLS 548
#define LOG_PFX "[logger] "

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t);
typedef void (*log_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t,
                         int64_t, int64_t);

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall);
static void log_openat(int64_t dirfd, int64_t file, int64_t flags,
                       int64_t mode, int64_t r8, int64_t r9, int64_t rax,
                       int64_t ret);
static void log_read(int64_t fd, int64_t buf, int64_t count, int64_t r10,
                     int64_t r8, int64_t r9, int64_t rax, int64_t ret);
static void log_write(int64_t fd, int64_t buf, int64_t count, int64_t r10,
                      int64_t r8, int64_t r9, int64_t rax, int64_t ret);
static void log_connect(int64_t sockfd, int64_t addr, int64_t addrlen,
                        int64_t r10, int64_t r8, int64_t r9, int64_t rax,
                        int64_t ret);
static void log_execve(int64_t pathname, int64_t argv, int64_t envp,
                       int64_t r10, int64_t r8, int64_t r9, int64_t rax,
                       int64_t ret);

static syscall_hook_fn_t original_syscall = NULL;
static log_fn_t logger_map[NUM_SYSCALLS];
static bool logging_pos[NUM_SYSCALLS];

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t r10, int64_t r8, int64_t r9, int64_t rax)
{
    int64_t ret = 0;
    log_fn_t log_fn;
    if (rax < NUM_SYSCALLS && (log_fn = logger_map[rax]) != NULL)
    {
        if (!logging_pos[rax])
            log_fn(rdi, rsi, rdx, r10, r8, r9, rax, ret);
        ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
        if (logging_pos[rax])
            log_fn(rdi, rsi, rdx, r10, r8, r9, rax, ret);
    }
    else
    {
        ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    }
    return ret;
}

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall)
{
    original_syscall = trigger_syscall;
    *hooked_syscall = syscall_hook_fn;
    memset(logger_map, 0, sizeof(logger_map));
    memset(logging_pos, true, sizeof(logging_pos));
    logger_map[SYS_read] = log_read;
    logger_map[SYS_write] = log_write;
    logger_map[SYS_connect] = log_connect;
    logger_map[SYS_execve] = log_execve;
    logging_pos[SYS_execve] = false;
    logger_map[SYS_openat] = log_openat;
}

static void log_openat(int64_t dirfd, int64_t file, int64_t flags,
                       int64_t mode, __attribute__((unused)) int64_t r8,
                       __attribute__((unused)) int64_t r9,
                       __attribute__((unused)) int64_t rax, int64_t ret)
{
    int fd = (int)dirfd;
    fprintf(stderr, "%sopenat(", LOG_PFX);
    if (fd == AT_FDCWD)
        fprintf(stderr, "AT_FDCWD");
    else
        fprintf(stderr, "%d", fd);

    fprintf(stderr, ", \"%s\", %#x, %#o) = %d\n", (const char *)file,
            (int)flags, (mode_t)mode, (int)ret);
}

static void log_read(int64_t fd, int64_t buf, int64_t count,
                     __attribute__((unused)) int64_t r10,
                     __attribute__((unused)) int64_t r8,
                     __attribute__((unused)) int64_t r9,
                     __attribute__((unused)) int64_t rax, int64_t ret)
{
    fprintf(stderr, "%sread(%d, \"", LOG_PFX, (int)fd);
    size_t output_len = count > 32 ? 32 : count;
    for (size_t i = 0; i < output_len; i++)
    {
        uint8_t data = ((uint8_t *)buf)[i];
        if (isprint(data) || isspace(data))
        {
            switch (data)
            {
            case '\t':
                fprintf(stderr, "\\t");
                break;
            case '\n':
                fprintf(stderr, "\\n");
                break;
            case '\r':
                fprintf(stderr, "\\r");
                break;
            default:
                fprintf(stderr, "%c", (char)data);
                break;
            }
        }
        else
        {
            fprintf(stderr, "\\x%02hhx", data);
        }
    }
    fprintf(stderr, "\"");
    if (count > 32)
        fprintf(stderr, "...");
    fprintf(stderr, ", %d) = %d\n", (int)count, (int)ret);
}

static void log_write(int64_t fd, int64_t buf, int64_t count,
                      __attribute__((unused)) int64_t r10,
                      __attribute__((unused)) int64_t r8,
                      __attribute__((unused)) int64_t r9,
                      __attribute__((unused)) int64_t rax, int64_t ret)
{
    fprintf(stderr, "%swrite(%d, \"", LOG_PFX, (int)fd);
    size_t output_len = count > 32 ? 32 : count;
    for (size_t i = 0; i < output_len; i++)
    {
        uint8_t data = ((uint8_t *)buf)[i];
        if (isprint(data) || isspace(data))
        {
            switch (data)
            {
            case '\t':
                fprintf(stderr, "\\t");
                break;
            case '\n':
                fprintf(stderr, "\\n");
                break;
            case '\r':
                fprintf(stderr, "\\r");
                break;
            default:
                fprintf(stderr, "%c", (char)data);
                break;
            }
        }
        else
        {
            fprintf(stderr, "\\x%02hhx", data);
        }
    }
    fprintf(stderr, "\"");
    if (count > 32)
        fprintf(stderr, "...");
    fprintf(stderr, ", %d) = %d\n", (int)count, (int)ret);
}

static void log_connect(int64_t sockfd, int64_t addr, int64_t addrlen,
                        __attribute__((unused)) int64_t r10,
                        __attribute__((unused)) int64_t r8,
                        __attribute__((unused)) int64_t r9,
                        __attribute__((unused)) int64_t rax, int64_t ret)
{
    fprintf(stderr, "%sconnect(%d, \"", LOG_PFX, (int)sockfd);
    const struct sockaddr *sock_addr = (struct sockaddr *)addr;
    char ip_str[INET6_ADDRSTRLEN];
    int port;
    switch (sock_addr->sa_family)
    {
    case AF_INET:
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        // char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, sizeof(ip_str));
        port = ntohs(addr_in->sin_port);
        fprintf(stderr, "%s:%d", ip_str, port);
        break;
    case AF_INET6:
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        // char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip_str, sizeof(ip_str));
        port = ntohs(addr_in6->sin6_port);
        fprintf(stderr, "%s:%d", ip_str, port);
        break;
    case AF_UNIX:
        struct sockaddr_un *addr_un = (struct sockaddr_un *)addr;
        fprintf(stderr, "UNIX:%s", addr_un->sun_path);
        break;
    }
    fprintf(stderr, "\", %d) = %d\n", (int)addrlen, (int)ret);
}

static void log_execve(int64_t pathname, int64_t argv, int64_t envp,
                       __attribute__((unused)) int64_t r10,
                       __attribute__((unused)) int64_t r8,
                       __attribute__((unused)) int64_t r9,
                       __attribute__((unused)) int64_t rax,
                       __attribute__((unused)) int64_t ret)
{
    fprintf(stderr, "%sexecve(\"%s\", %p, %p)\n", LOG_PFX, (const char *)pathname,
            (char *const)argv, (char *const)envp);
}