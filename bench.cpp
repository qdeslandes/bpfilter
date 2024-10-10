#include <cstdio>
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <cerrno>
#include <sstream>
#include <iostream>
#include <array>
#include <unistd.h>
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <memory>
#include <chrono>
#include <thread>
#include <bpf/bpf.h>
#include <tuple>
#include <fcntl.h>
#include <benchmark/benchmark.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>

#if defined(__i386__)
#define _BF_NR_bpf 357
#elif defined(__x86_64__)
#define _BF_NR_bpf 321
#elif defined(__aarch64__)
#define _BF_NR_bpf 280
#else
#error _BF_NR_bpf not defined. bpfilter does not support your arch.
#endif

namespace bpfilter {

int bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
    int r = (int)syscall(_BF_NR_bpf, cmd, attr, sizeof(*attr));
    if (r < 0)
        return -errno;

    return r;
}

class BfDaemonOptions
{
public:
    BfDaemonOptions &transient()
    {
        options_.push_back("--transient");
        return *this;
    }

    BfDaemonOptions &noCli()
    {
        options_.push_back("--no-cli");
        return *this;
    }

    BfDaemonOptions &noIptables()
    {
        options_.push_back("--no-iptables");
        return *this;
    }

    BfDaemonOptions &noNftables()
    {
        options_.push_back("--no-nftables");
        return *this;
    }

    BfDaemonOptions &bufferLen(::std::size_t len)
    {
        options_.push_back("--buffer-len");
        options_.push_back(::std::to_string(len));
        return *this;
    }

    BfDaemonOptions &verbose(const ::std::string &component)
    {
        options_.push_back("--verbose");
        options_.push_back(component);
        return *this;
    }

    ::std::string str() const
    {
        ::std::stringstream opts;

        for (::std::size_t i = 0; i < options_.size(); ++i) {
            opts << options_[i];
            if (i != options_.size() - 1)
                opts << " ";
        }

        return opts.str();
    }

    ::std::vector<::std::string> get() const
    {
        return options_;
    }

    ::std::vector<const char *> raw() const
    {
        ::std::vector<const char *> options;

        for (const auto &opt: options_)
            options.push_back(opt.c_str());

        return options;
    }

private:
    ::std::vector<::std::string> options_;
};

int execccc(::std::string bin, ::std::vector<::std::string> args, int *out = nullptr, int *err = nullptr)
{
    int stdout_pipe[2];
    int stderr_pipe[2];
    pid_t pid;

    std::vector<const char *> args_;
    args_.push_back(bin.c_str());
    for (const auto &arg: args)
        args_.push_back(arg.c_str());
    args_.push_back(nullptr);

    if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0)
        throw ::std::invalid_argument("failed to create pipes");

    pid = fork();
    if (pid < 0)
        throw ::std::invalid_argument("failed to fork");

    if (pid == 0) {
        int r = 0;
        dup2(stdout_pipe[1], STDOUT_FILENO);
        ::std::cout << "dup2 stdout " << r << ::std::endl;
        r = dup2(stderr_pipe[1], STDERR_FILENO);
        ::std::cout << "dup2 stderr " << r << ::std::endl;


        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        std::string s = "stdout";
        write(1, s.c_str(), s.size() + 1);

        ::std::cout << "go" << ::std::endl;

        int rrr = execvp(bin.c_str(), (char *const *)(args_.data()));
        throw ::std::invalid_argument("execvp failed: " + ::std::string(::std::strerror(errno)));
    }

    if (out){
        ::std::cout << "PIPE OPEN" << ::std::endl;
        *out = stdout_pipe[0];
    } else {
        ::std::cout << "PIPE close" << ::std::endl;
        close(stdout_pipe[0]);
    }
    if (err)
        *err = stderr_pipe[0];
    else
        close(stderr_pipe[0]);

    return pid;
}

::std::string read_fd(int fd)
{
    ssize_t len;
    char buffer[1024] = {};
    ::std::string data;


    while ((len = read(fd, buffer, 1024)) >= 0)
        data += ::std::string(buffer, len);

    if (len == 0)
        ::std::cout << "EOF, all read!" << ::std::endl;
    else if (len < 0 && errno != EAGAIN)
        ::std::cout << "GOT ERROR: " << errno << ::std::endl;

    return data;
}

::std::tuple<int, ::std::string, ::std::string> run(::std::string bin, ::std::vector<::std::string> args)
{
    int out, err;
    int fd = execccc(bin, args, &out, &err);

    int status;

    int flags;
    flags = fcntl(out, F_GETFL, 0);
    fcntl(out, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(err, F_GETFL, 0);
    fcntl(err, F_SETFL, flags | O_NONBLOCK);


    (void)waitpid(fd, &status, 0);

    ::std::string strerr = read_fd(err);
    ::std::string strout = read_fd(out);
    close(out);
    close(err);

    return {WEXITSTATUS(status), strout, strerr};
}

class BfDaemon
{
public:
    BfDaemon(const ::std::string &path = "bpfilter", BfDaemonOptions options = BfDaemonOptions()):
        path_{path},
        options_{options}
    {

    }

    void start()
    {
        ::std::cout << path_ << ::std::endl;
        pid_ = execccc(path_, options_.get(), &out, &err);

        int flags = fcntl(out, F_GETFL, 0);
        fcntl(out, F_SETFL, flags | O_NONBLOCK);
        flags = fcntl(err, F_GETFL, 0);
        fcntl(err, F_SETFL, flags | O_NONBLOCK);

        while (true) {
            int status;
            int r = waitpid(pid_, &status, WNOHANG);
            if (r == -1) {
                throw ::std::runtime_error("error...");
            } else if (r != 0) {
                ::std::cout << "Log: " << read_fd(err) << ::std::endl;
                ::std::cout << "Log: " << read_fd(out) << ::std::endl;
                throw ::std::runtime_error("daemon is dead...");
            }

            std::string data = read_fd(err);
            if (data.find("waiting for requests...") != std::string::npos) {
                std::cout << "Daemon is ready!" << '\n';
                break;
            }

            if (data.size()) {
                ::std::cout << "not ready but: " << ::std::endl;
                ::std::cout << data << ::std::endl;
                ::std::cout << "end" << ::std::endl;
            }
            ::std::string eee = read_fd(err);
            if (eee.size()) {
                ::std::cout << "stderr: " << ::std::endl;
                ::std::cout << eee << ::std::endl;
                ::std::cout << "end stderr" << ::std::endl;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void stop()
    {
        int r = kill(pid_, SIGINT);
        if (r < 0)
            throw ::std::runtime_error("failed to send SIGINT " + ::std::string(::std::strerror(errno)));

        int status;
        (void)waitpid(pid_, &status, 0);

        ::std::cout << read_fd(out) << ::std::endl;
        ::std::cout << read_fd(err) << ::std::endl;

        //pclose(process_);
    }

private:
    ::std::string path_;
    BfDaemonOptions options_;
    FILE *process_ = nullptr;
    pid_t pid_;
    int out;
    int err;

    ::std::string buildCmd() const
    {
        return path_ + " " + options_.str();
    }
};

class Program
{
public:
    Program(std::string name): name_{name}
    {

    }

    Program(Program &other) = delete;

    Program(Program &&other)
    {
        if (fd_ != -1)
            ::close(fd_);

        fd_ = other.fd_;
        other.fd_ = -1;
    }

    Program& operator=(Program& other) = delete;

    Program& operator=(Program&& other)
    {
        if (fd_ != -1)
            ::close(fd_);

        fd_ = other.fd_;
        other.fd_ = -1;

        return *this;
    }

    ~Program()
    {
        if (fd_ != -1) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    int open()
    {
        uint32_t id = 0;
        int r;

        while (true) {
            r = bpf_prog_get_next_id(id, &id);
            if (r < 0) {
                ::std::cerr << "call to bpf_prog_get_next_id() failed: " << ::strerror(r) << ::std::endl;
                return r;
            }

            int prog_fd = bpf_prog_get_fd_by_id(id);
            if (prog_fd < 0) {
                ::std::cerr << "call to bpf_prog_get_fd_by_id() failed: " << ::strerror(prog_fd) << ::std::endl;
                return prog_fd;
            }

            struct bpf_prog_info info = {};
            uint32_t len = sizeof(info);
            r = bpf_prog_get_info_by_fd(prog_fd, &info, &len);
            if (r < 0) {
                ::close(prog_fd);
                ::std::cerr << "call to bpf_prog_get_info_by_fd() failed: " << ::strerror(r) << ::std::endl;
                return r;
            }

            if (::std::string(info.name) == name_) {
                fd_ = prog_fd;
                return 0;
            }

            ::close(prog_fd);
        }

        return 0;
    }

    void close()
    {
        ::close(fd_);
        fd_ = -1;
    }

    int run(int expect, int iters, void *pkt, int len)
    {
        LIBBPF_OPTS(
            bpf_test_run_opts,
            opts,
            .data_in = (const void*)pkt,
            .data_size_in = len,
            .repeat = (int)iters
        );

        int r = bpf_prog_test_run_opts(fd_, &opts);
        if (r < 0){
            ::std::cout << "Failed to run prog " << r << ::std::endl;
            return r;
            }

        return 0;
    }

private:
    ::std::string name_;
    int fd_ = -1;
};

class BfChain
{
public:
    BfChain() {}

    BfChain(BfChain &other) = delete;
    BfChain(BfChain &&other) = delete;
    BfChain &operator=(BfChain &other) = delete;
    BfChain &operator=(BfChain &&other) = delete;

    BfChain& operator<<(const ::std::string &rule) {
        m_rules.push_back(rule);
        return *this;
    }

    BfChain& repeatRule(const ::std::string &rule, ::std::size_t count) {
        for (::std::size_t i = 0; i < count; ++i)
        m_rules.push_back(rule);

        return *this;
    }

    Program getProgram() const
    {
        Program p("bf_benchmark");

        if (p.open())
            throw ::std::runtime_error("can't open program!");

        return ::std::move(p);
    }

    int apply() const
    {

        ::std::vector<::std::string> args;
        args.push_back("--str");
        args.push_back("chain BF_HOOK_XDP{ifindex=1,name=bf_benchmark,attach=no} policy ACCEPT rule meta.l4_proto tcp counter ACCEPT");
        const auto [r, out, err] = run("/home/quentin/Projects/bpfilter/build/output/bin/bfcli", args);

        if (r != 0) {
            ::std::cout << err << ::std::endl;
            throw ::std::runtime_error("bfcli returned with status " + ::std::to_string(r));
        }

        return 0;
    }

private:
    ::std::vector<::std::string> m_rules;
    int fd_ = -1;

    ::std::string ruleset() const
    {
        ::std::string chain = "chain BF_HOOK_CGROUP_INGRESS{cgroup=invalid,attach=no,name=bf_benchmark} policy ACCEPT ";

        for (const auto &s: m_rules)
        chain += (s + " ");

        return chain;
    }
};

}

constexpr uint8_t kLocalhostIPv6TCPPkt[] = {

    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x7a,
    0x69, 0x7a, 0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x02, 0x20, 0x00, 0x9a, 0xbf, 0x00, 0x0};

static void BM_test(benchmark::State& state) {
    ::bpfilter::BfChain chain;
    chain.apply();
    auto p = chain.getProgram();

    while (state.KeepRunningBatch(10000)) {
        p.run(2, 10000, (void *)kLocalhostIPv6TCPPkt, sizeof(kLocalhostIPv6TCPPkt));
    }
}
BENCHMARK(BM_test);

int main(int argc, char* argv[])
{
    if (geteuid() != 0)
        throw std::runtime_error("the benchmark should be run as root");

    auto d = bpfilter::BfDaemon(
        "/home/quentin/Projects/bpfilter/build/output/bin/bpfilter",
        bpfilter::BfDaemonOptions().transient().noIptables().noNftables()
    );

    d.start();

   ::benchmark::Initialize(&argc, argv);
   ::benchmark::RunSpecifiedBenchmarks();

    d.stop();

    return 0;
}
