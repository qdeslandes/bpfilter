/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/mount.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "core/helper.h"
#include "core/logger.h"

#define FSCONFIG_SET_FLAG 0
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_CMD_CREATE 6

#define SOCK_IN_WRITE "/tmp/to_out.sock"
#define SOCK_OUT_WRITE "/tmp/to_in.sock"
/*
static inline int fsopen(const char *fsname, unsigned int flags)
{
	int r;

    r = syscall(__NR_fsopen, fsname, flags);
    if (r < 0)
        return -errno;

    return r;
}

static inline int fsmount(int fd, unsigned int flags, unsigned int attr_flags)
{
    int r;

    r = syscall(__NR_fsmount, fd, flags, attr_flags);
    if (r < 0)
        return -errno;

    return r;
}

static inline int move_mount(int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned int flags)
{
    int r;

    r = syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
    if (r)
        return -errno;

    return 0;
}

static inline int fsconfig(int fd, unsigned int cmd, const char *key, const char *value, int aux)
{
	int r;

    r = syscall(__NR_fsconfig, fd, cmd, key, value, aux);
    if (r)
        return -errno;

    return r;
}
*/

void print_fd_info(int fd)
{
    char b[1024];

    snprintf(b, 1024, "cat /proc/self/fdinfo/%d", fd);
    system(b);
}

static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
    int r = (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
    if (r < 0)
        return -errno;

    return r;
}

#define CMD_LEN 64
static char cmd[CMD_LEN];

struct st_opts
{
    const char *socket_path;
};

static error_t st_opts_parser(int key, const char *arg, struct argp_state *state)
{
    struct st_opts *opts = state->input;

    switch (key) {
    case 's':
        opts->socket_path = arg;
        break;
    case ARGP_KEY_END:
        if (!opts->socket_path)
            return bf_err_r(-EINVAL, "--socket argument required");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static inline void usage(void)
{
    bf_err("usage: setup_token_bin COMMAND [OPTIONS...]");
}

int send_fd(int sock_fd, int fd)
{
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    int fds[1] = { fd };
    char iobuf[1];
    struct iovec io = {
        .iov_base = iobuf,
        .iov_len = sizeof(iobuf),
    };
    union {
        char buf[CMSG_SPACE(sizeof(fds))];
        struct cmsghdr align;
    } u;
    int r;

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

    r = sendmsg(sock_fd, &msg, 0);
    if (r < 0)
        return bf_err_r(errno, "send_fd: failed to send message");
    if (r != 1)
        return bf_err_r(-EINVAL, "send_fd: unexpected amount of data sent (%d)", r);

    return 0;
}

int recv_fd(int sock_fd)
{
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    int fds[1];
    char iobuf[1];
    struct iovec io = {
        .iov_base = iobuf,
        .iov_len = sizeof(iobuf),
    };
    union {
        char buf[CMSG_SPACE(sizeof(fds))];
        struct cmsghdr align;
    } u;
    int r;

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);

    r = recvmsg(sock_fd, &msg, 0);
    if (r < 0)
        return bf_err_r(errno, "recv_fd: failed to receive message");
    if (r != 1)
        return bf_err_r(r, "recv_fd: unexpected amount of data received (%d)", r);

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg)
        return bf_err_r(-EINVAL, "recv_fd: cmsg is NULL");
    if (cmsg->cmsg_len != CMSG_LEN(sizeof(fds)))
        return bf_err_r(-EINVAL, "recv_fd: cmsg has unexpected length");
    if (cmsg->cmsg_level != SOL_SOCKET)
        return bf_err_r(-EINVAL, "recv_fd: cmsg has unexpected level");
    if (cmsg->cmsg_type != SCM_RIGHTS)
        return bf_err_r(-EINVAL, "recv_fd: cmsg has unexpected type");

    memcpy(fds, CMSG_DATA(cmsg), sizeof(fds));

    return fds[0];
}

int create_token(int bpffs_fd)
{
    union bpf_attr attr = {};
    int r;

    attr.token_create.bpffs_fd = bpffs_fd;

    r = bpf(BPF_TOKEN_CREATE, &attr);
    if (r)
        return bf_err_r(r, "create_token: failed to create BPF token");

    return 0;
}

int do_in(const struct st_opts *opts)
{
    _cleanup_close_ int sock_fd = -1;
    _cleanup_close_ int fd = -1;
    _cleanup_close_ int mount_fd = -1;
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int token_fd = -1;
    struct sockaddr_un addr = {};
    int r;

    /**
     * Get socket
     */
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return bf_err_r(errno, "do_in: can't create socket");

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, opts->socket_path, sizeof(addr.sun_path) - 1);

    r = connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0)
        return bf_err_r(errno, "do_in: failed to connect to socket at %s", opts->socket_path);

    /**
     * Remount /
     */
    r = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0);
    if (r)
        return bf_err_r(errno, "do_in: failed to remount '/'");
    bf_info("do_in: remounted '/'");

    /**
     * Open bpffs
     */
    fd = fsopen("bpf", 0);
    if (fd < 0)
        return bf_err_r(fd, "do_in: failed to open BPF filesystem");
    bf_info("do_in: BPF filesystem opened at FD %d", fd);

    // Send bpffs FD to outside
    r = send_fd(sock_fd, fd);
    if (r)
        return bf_err_r(r, "do_in: failed to send file descriptor");
    bf_info("do_in: sent bpffs FD outside");

    mount_fd = recv_fd(sock_fd);
    if (mount_fd < 0)
        return bf_err_r(mount_fd, "do_in: failed to receive mount fd");
    bf_info("do_in: receive mount FD from outside");

    bpffs_fd = openat(mount_fd, ".", 0, O_RDWR);
    if (bpffs_fd < 0)
        return bf_err_r(errno, "do_in: failed to open bpffs_fd");
    bf_info("do_in: opened bpffs_fd");

	token_fd = bpf_token_create(bpffs_fd, NULL);
	if (token_fd < 0)
        return bf_err_r(token_fd, "do_in: failed to create a new BPF token");
    bf_info("do_in: created a new BPF token!");

    return 0;
}

int do_out(const struct st_opts *opts)
{
    _cleanup_close_ int sock_fd = -1;
    _cleanup_close_ int client_fd = -1;
    _cleanup_close_ int mnt_fd = -1;
    _cleanup_close_ int bpffs_fd = -1;
    struct sockaddr_un addr = {};
    int r;

    /**
     * Get socket
     */
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return bf_err_r(errno, "do_out: failed to create socket");

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, opts->socket_path, sizeof(addr.sun_path) - 1);

    r = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0)
        return bf_err_r(errno, "do_out: failed to bind socket to %s", opts->socket_path);

    r = listen(sock_fd, 1);
    if (r)
        return bf_err_r(errno, "do_out: failed to listen to connections");

    client_fd = accept(sock_fd, NULL, NULL);
    if (client_fd < 0)
        return bf_err_r(errno, "do_out: failed to accept connection");

    /**
     * Receive a bpffs FD
     */
    bpffs_fd = recv_fd(client_fd);
    if (bpffs_fd < 0)
        return bf_err_r(bpffs_fd, "do_out: failed to receive file descriptor");
    bf_info("do_out: receive bpffs FD from inside");

    r = fsconfig(bpffs_fd, FSCONFIG_SET_STRING, "delegate_cmds", "any", 0);
    if (r)
        return bf_err_r(r, "do_out: failed to set 'delegate_cmds'");
    bf_info("do_out: configured 'delegate_cmds'");

    r = fsconfig(bpffs_fd, FSCONFIG_SET_STRING, "delegate_maps", "any", 0);
    if (r)
        return bf_err_r(r, "do_out: failed to set 'delegate_maps'");
    bf_info("do_out: configured 'delegate_maps'");

    r = fsconfig(bpffs_fd, FSCONFIG_SET_STRING, "delegate_progs", "any", 0);
    if (r)
        return bf_err_r(r, "do_out: failed to set 'delegate_progs'");
    bf_info("do_out: configured 'delegate_progs'");

    r = fsconfig(bpffs_fd, FSCONFIG_SET_STRING, "delegate_attachs", "any", 0);
    if (r)
        return bf_err_r(r, "do_out: failed to set 'delegate_attachs'");
    bf_info("do_out: configured 'delegate_attachs'");

    r = fsconfig(bpffs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
    if (r)
        return bf_err_r(r, "do_out: failed to create fsconfig");
    bf_info("do_out: created fsconfig command");

    mnt_fd = fsmount(bpffs_fd, 0, 0);
    if (mnt_fd < 0)
        return bf_err_r(mnt_fd, "do_out: failed to fsmount bpffs");
    bf_info("do_out: opened a mount FD for bpffs");

    /**
     * Send the FD back
     */
    r = send_fd(client_fd, mnt_fd);
    if (r)
        return bf_err_r(r, "do_out: failed to send file descriptor");
    bf_info("do_out: mount FD sent back inside");

    return 0;
}

int main(int argc, char *argv[])
{
    static struct argp_option options[] = {
        {"socket", 's', "SOCKET_PATH", 0, "Path to the socket to use to communicate", 0},
        {0},
    };

    const char *command;
    struct st_opts opts = {};
    struct argp argp = {
        options, (argp_parser_t)st_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    int r;

    if (argc < 2 || argv[1][0] == '-') {
        usage();
        return EXIT_FAILURE;
    }

    command = argv[1];

    snprintf(cmd, CMD_LEN, "%s %s", argv[0], argv[1]);
    argv++;
    argc--;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    if (bf_streq(command, "in")) {
        bf_info("running from within the container");
        r = do_in(&opts);
    } else if (bf_streq(command, "out")) {
        bf_info("running from outside the container");
        r = do_out(&opts);
    } else {
        usage();
        return EXIT_FAILURE;
    }

    return r;

    /*
    union bpf_attr attr = {};
    int r;

    if (argc == 1)  {
        printf("allowing a token\n");
        int fd = fsopen("bpf", 0);
        if (fd < 0) {
            fprintf(stderr, "failed to open bpf filesystem: %s\n", strerror(-fd));
            return EXIT_FAILURE;
        }


        print_fd_info(fd);
        printf("Fd %d pid %d\n", fd, getpid());
        close(fd);
    }

    if (argc == 2) {
        printf("Creating a token\n");

        int fd = fsopen("bpf", 0);
        if (fd < 0) {
            fprintf(stderr, "failed to open bpf filesystem: %s\n", strerror(-fd));
            return EXIT_FAILURE;
        }
        printf("Fd %d pid %d\n", fd, getpid());
        print_fd_info(fd);


        attr.token_create.bpffs_fd = fd;

        r = bpf(BPF_TOKEN_CREATE, &attr);
        if (r <= 0) {
            fprintf(stderr, "failed to create a BPF token: %s\n", strerror(-r));
            close(fd);
            return EXIT_FAILURE;
        }
        sleep(10000);

        close(fd);
    }
        */

    return 0;
}
