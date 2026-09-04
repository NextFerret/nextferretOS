#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cerrno>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>
#include <utility>
#include <set>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <csignal>
#include <mutex>
#include <future>
#include <apt-pkg/init.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/acquire.h>
#include <apt-pkg/acquire-item.h>
#include <apt-pkg/algorithms.h>
#include <apt-pkg/packagemanager.h>
#include <apt-pkg/pkgrecords.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/policy.h>
#include <apt-pkg/upgrade.h>
#include <apt-pkg/error.h>
#include <apt-pkg/version.h>
#include <apt-pkg/install-progress.h>
#include <apt-pkg/debfile.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/tagfile.h>
#include <apt-pkg/update.h>
#include <memory>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x05000000U
#endif

#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif

#ifndef SECCOMP_RET_DATA
#define SECCOMP_RET_DATA 0x0000ffffU
#endif

#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 0xc000003e
#endif

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xc00000b7
#endif

#if defined(__x86_64__)
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SECCOMP_TARGET_ARCH AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#define SECCOMP_TARGET_ARCH 0x40000003
#elif defined(__arm__)
#define SECCOMP_TARGET_ARCH 0x40000028
#else
#define SECCOMP_TARGET_ARCH 0
#endif


using namespace std;
namespace fs = std::filesystem;

const string TREE_ROOT = "/nsm/napt/root";
const string NF_TREE_BIN = "/usr/bin/nsm";
const string AUTO_SNAP_DIR = "/nsm/snapshots/auto";
const string NAPT_ETC_DIR = "/etc/napt";
const string NAPT_SOURCES_FILE = "/etc/napt/sources.list";
const string NAPT_SOURCES_DIR  = "/etc/napt/sources.list.d";
const string NAPT_CACHE_DIR = "/etc/napt/cache";
const string NAPT_ALLOWED_FILE = "/etc/napt/allowed";

static bool assume_yes = false;
static bool g_enable_seccomp = true;
static std::atomic<bool> sandbox_created_and_mounted(false);

// Forward declarations for LVM/root-device helpers (defined later in this file,
// but used earlier by create_snapshot()).
static string get_root_device();
static string get_root_fstype();
static string get_vg_name(const string& lv_path);
static bool is_lv_thin(const string& lv_path);
static double get_vg_free_gb(const string& vg_name);

class ChrootSeccompManager {
public:
    static bool apply_filter(string& err_out) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            err_out = "Failed to set PR_SET_NO_NEW_PRIVS: " + string(strerror(errno));
            return false;
        }

        vector<sock_filter> filter;

        filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)));

#if SECCOMP_TARGET_ARCH != 0
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_TARGET_ARCH, 1, 0));
        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
#endif

        filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)));

        vector<int> blocked_syscalls;

#ifdef __NR_reboot
        blocked_syscalls.push_back(__NR_reboot);
#endif
#ifdef __NR_init_module
        blocked_syscalls.push_back(__NR_init_module);
#endif
#ifdef __NR_delete_module
        blocked_syscalls.push_back(__NR_delete_module);
#endif
#ifdef __NR_finit_module
        blocked_syscalls.push_back(__NR_finit_module);
#endif
#ifdef __NR_kexec_load
        blocked_syscalls.push_back(__NR_kexec_load);
#endif
#ifdef __NR_kexec_file_load
        blocked_syscalls.push_back(__NR_kexec_file_load);
#endif
#ifdef __NR_swapon
        blocked_syscalls.push_back(__NR_swapon);
#endif
#ifdef __NR_swapoff
        blocked_syscalls.push_back(__NR_swapoff);
#endif
#ifdef __NR_acct
        blocked_syscalls.push_back(__NR_acct);
#endif
#ifdef __NR_ptrace
        blocked_syscalls.push_back(__NR_ptrace);
#endif
#ifdef __NR_bpf
        blocked_syscalls.push_back(__NR_bpf);
#endif
#ifdef __NR_userfaultfd
        blocked_syscalls.push_back(__NR_userfaultfd);
#endif
#ifdef __NR_syslog
        blocked_syscalls.push_back(__NR_syslog);
#endif
#ifdef __NR_iopl
        blocked_syscalls.push_back(__NR_iopl);
#endif
#ifdef __NR_ioperm
        blocked_syscalls.push_back(__NR_ioperm);
#endif
#ifdef __NR_vmsplice
        blocked_syscalls.push_back(__NR_vmsplice);
#endif
#ifdef __NR_add_key
        blocked_syscalls.push_back(__NR_add_key);
#endif
#ifdef __NR_request_key
        blocked_syscalls.push_back(__NR_request_key);
#endif
#ifdef __NR_keyctl
        blocked_syscalls.push_back(__NR_keyctl);
#endif
#ifdef __NR_pivot_root
        blocked_syscalls.push_back(__NR_pivot_root);
#endif
#ifdef __NR_clock_settime
        blocked_syscalls.push_back(__NR_clock_settime);
#endif
#ifdef __NR_settimeofday
        blocked_syscalls.push_back(__NR_settimeofday);
#endif

        for (int sys_nr : blocked_syscalls) {
            filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)sys_nr, 0, 1));
            filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
        }

        filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

        struct sock_fprog prog;
        prog.len = (unsigned short)filter.size();
        prog.filter = filter.data();

        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            err_out = "Failed to load SECCOMP filter: " + string(strerror(errno));
            return false;
        }

        return true;
    }
};


bool read_text_file(const string& path, string& content);
bool write_text_file(const string& path, const string& content);

struct ConfigBackup {
    string os_release_orig;
    string apt_sources_orig;
    string napt_sources_orig;

    string os_release_new;
    string apt_sources_new;
    string napt_sources_new;

    bool backed_up = false;
    bool has_new = false;

    void backup() {
        os_release_orig.clear();
        apt_sources_orig.clear();
        napt_sources_orig.clear();
        read_text_file("/etc/os-release", os_release_orig);
        read_text_file("/etc/apt/sources.list", apt_sources_orig);
        read_text_file("/etc/napt/sources.list", napt_sources_orig);
        backed_up = true;
    }

    void set_new(const string& os, const string& apt, const string& napt) {
        os_release_new = os;
        apt_sources_new = apt;
        napt_sources_new = napt;
        has_new = true;
    }

    void restore_orig() {
        if (!backed_up) return;
        if (!os_release_orig.empty()) write_text_file("/etc/os-release", os_release_orig);
        else unlink("/etc/os-release");
        if (!apt_sources_orig.empty()) write_text_file("/etc/apt/sources.list", apt_sources_orig);
        else unlink("/etc/apt/sources.list");
        if (!napt_sources_orig.empty()) write_text_file("/etc/napt/sources.list", napt_sources_orig);
        else unlink("/etc/napt/sources.list");
    }

    void apply_new() {
        if (!has_new) return;
        if (!os_release_new.empty()) write_text_file("/etc/os-release", os_release_new);
        if (!apt_sources_new.empty()) write_text_file("/etc/apt/sources.list", apt_sources_new);
        if (!napt_sources_new.empty()) write_text_file("/etc/napt/sources.list", napt_sources_new);
    }
};

static ConfigBackup global_config_backup;

struct NaptSource {
    string base_url;
    string release;
};

struct NaptRepoMetadata {
    string base_url;
    string release;
    map<string, pair<string, string>> packages;
    vector<string> required_packages;
    map<string, string> replaces;
};

struct NaptPackageCandidate {
    bool found = false;
    string base_url;
    string release;
    string file_name;
    string version;
    string sha256;
    string actual_pkg_name;
    string original_query_name;
    bool is_replacement = false;
};

struct AptPackageState {
    bool found = false;
    bool installed = false;
    string installed_version;
    string candidate_version;
};

struct InstallDecision {
    string package_name;
    string apt_argument;
    string selected_version;
    bool from_napt = false;
};

void perform_install_transaction(const vector<string>& pkgs, bool apply_host, bool is_upgrade = false);
bool run_libapt_transaction(const string& action, const vector<string>& targets, int status_fd, bool quiet);

bool nf_tree_available() {
    return access(NF_TREE_BIN.c_str(), X_OK) == 0;
}

void show_help() {
    string cyan = "\033[1;36m";
    string green = "\033[1;32m";
    string yellow = "\033[1;33m";
    string bold = "\033[1m";
    string reset = "\033[0m";

    cout << cyan << bold << "New Advanced Packaging Tool (NAPT) - Version 4.1" << reset << "\n";
    cout << "Atomic, Transactional & Hardened Package Management for Arvor Linux\n\n";
    cout << bold << "Usage:" << reset << " napt [command] [packages/options]\n\n";
    cout << bold << "Core Transaction Commands:" << reset << "\n";
    cout << "  " << green << "install" << reset << " <pkgs...>       Install packages or local .deb archives (sandbox-verified)\n";
    cout << "  " << green << "remove" << reset << " <pkgs...>        Safely remove packages from the system\n";
    cout << "  " << green << "purge" << reset << " <pkgs...>         Remove packages along with all configuration files\n";
    cout << "  " << green << "upgrade" << reset << " [pkgs...]      Upgrade all or specified packages transactionally\n";
    cout << "  " << green << "dist-upgrade" << reset << "          Perform a complete system release distribution upgrade\n";
    cout << "  " << green << "rollback" << reset << "              Revert the last transaction using pre-transaction snapshot\n\n";
    cout << bold << "Query & Inspection Commands:" << reset << "\n";
    cout << "  " << yellow << "search" << reset << " <term> [-p N]   Search package index by keyword with pagination\n";
    cout << "  " << yellow << "info" << reset << " <pkg>             Display detailed package origin, version, SHA256 & replaces\n";
    cout << "  " << yellow << "why" << reset << " <pkg>              Explain why a package is installed (reverse dependency tree)\n";
    cout << "  " << yellow << "depends" << reset << " <pkg>          List forward dependencies (Depends, Recommends, Suggests)\n";
    cout << "  " << yellow << "list" << reset << "                 List all currently installed packages on the system\n";
    cout << "  " << yellow << "stats" << reset << "                Display repository, package count and cache disk usage\n";
    cout << "  " << yellow << "history" << reset << "              Display recent package transaction history log\n\n";
    cout << bold << "Maintenance Commands:" << reset << "\n";
    cout << "  sync                 Refresh repository metadata concurrently with SHA256 validation\n";
    cout << "  clean                Clear the entire NAPT package download cache\n";
    cout << "  autoclean            Clear obsolete and stale packages from cache\n\n";
    cout << bold << "Transaction Flags:" << reset << "\n";
    cout << "  --apply-host         Skip sandbox test and apply transaction directly to host\n";
    cout << "  --no-seccomp         Disable BPF SECCOMP syscall filtering inside sandbox\n";
    cout << "  -y, --yes            Assume yes to all confirmation prompts\n";
    cout << "  --vb                 Enable verbose debug logging for transactions\n";
    cout << "  -h, --help           Show this comprehensive help screen\n\n";
    cout << "                 This napt Has Super Cow Powers.\n";
}

static bool wait_for_child(pid_t pid, int& status) {
    status = 0;
    while (true) {
        pid_t ret = waitpid(pid, &status, 0);
        if (ret == pid) return true;
        if (ret == -1 && errno == EINTR) continue;
        return false;
    }
}

static void exec_abs_argv(const vector<char*>& argv_ptrs) {
    if (argv_ptrs.empty() || argv_ptrs[0] == nullptr) _exit(127);
    const char* binary = argv_ptrs[0];
    if (strchr(binary, '/')) {
        execv(binary, const_cast<char* const*>(argv_ptrs.data()));
    } else {
        const char* paths[] = {"/usr/bin", "/bin", "/usr/sbin", "/sbin"};
        char fullpath[4096];
        for (size_t i = 0; i < 4; ++i) {
            snprintf(fullpath, sizeof(fullpath), "%s/%s", paths[i], binary);
            execv(fullpath, const_cast<char* const*>(argv_ptrs.data()));
        }
    }
    _exit(127);
}

static int exec_argv(const vector<string>& args, int stdout_fd = -1, int stderr_fd = -1, int extra_fd = -1) {
    if (args.empty()) return 1;

    pid_t pid = fork();
    if (pid < 0) return 1;

    if (pid == 0) {
        int devnull_r = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }

        if (stdout_fd >= 0 && stdout_fd != STDOUT_FILENO)
            dup2(stdout_fd, STDOUT_FILENO);
        if (stderr_fd >= 0 && stderr_fd != STDERR_FILENO)
            dup2(stderr_fd, STDERR_FILENO);
        if (extra_fd >= 0 && extra_fd != 3) {
            dup2(extra_fd, 3);
            fcntl(3, F_SETFD, 0);
        }

        if (stdout_fd >= 0 && stdout_fd != STDOUT_FILENO &&
            stdout_fd != STDERR_FILENO && stdout_fd != 3)
            close(stdout_fd);
        if (stderr_fd >= 0 && stderr_fd != STDERR_FILENO &&
            stderr_fd != STDOUT_FILENO && stderr_fd != 3 &&
            stderr_fd != stdout_fd)
            close(stderr_fd);
        if (extra_fd >= 0 && extra_fd != 3 &&
            extra_fd != STDOUT_FILENO && extra_fd != STDERR_FILENO)
            close(extra_fd);

        DIR* dir = opendir("/proc/self/fd");
        if (dir) {
            int dir_fd = dirfd(dir);
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                int fd = atoi(entry->d_name);
                if (fd > 2 && fd != extra_fd && fd != dir_fd) {
                    close(fd);
                }
            }
            closedir(dir);
        } else {
            int max_fd = static_cast<int>(sysconf(_SC_OPEN_MAX));
            if (max_fd < 0 || max_fd > 4096) max_fd = 1024;
            for (int fd = 4; fd < max_fd; ++fd) close(fd);
        }

        vector<char*> argv_ptrs;
        argv_ptrs.reserve(args.size() + 1);
        for (const auto& a : args) argv_ptrs.push_back(const_cast<char*>(a.c_str()));
        argv_ptrs.push_back(nullptr);

        exec_abs_argv(argv_ptrs);
    }

    int status = 0;
    wait_for_child(pid, status);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

static int exec_argv_devnull_out(const vector<string>& args) {
    int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int rc = exec_argv(args, devnull, devnull);
    if (devnull >= 0) close(devnull);
    return rc;
}

static string exec_argv_capture(const vector<string>& args) {
    if (args.empty()) return "";

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return "";

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return ""; }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        int devnull_r = open("/dev/null", O_RDONLY);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }
        for (int fd = 3; fd < 1024; ++fd) close(fd);

        vector<char*> argv_ptrs;
        argv_ptrs.reserve(args.size() + 1);
        for (const auto& a : args) argv_ptrs.push_back(const_cast<char*>(a.c_str()));
        argv_ptrs.push_back(nullptr);
        exec_abs_argv(argv_ptrs);
    }

    close(pipefd[1]);
    char buf[512];
    string result;
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        result.append(buf, n);
    close(pipefd[0]);

    int status = 0;
    wait_for_child(pid, status);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return result;
    return "";
}

bool create_snapshot(const string& name) {
    if (nf_tree_available()) {
        if (exec_argv_devnull_out({NF_TREE_BIN, "create", name}) == 0) return true;
    }
    string root_dev = get_root_device();
    string vg_name = get_vg_name(root_dev);
    if (!root_dev.empty() && !vg_name.empty()) {
        string snap_name = name + "_" + to_string(time(nullptr));
        return exec_argv_devnull_out({"lvcreate", "-s", "--name", snap_name, "-k", "n", root_dev}) == 0;
    }
    return false;
}

enum class PrecheckResult { Proceed, NoChanges, Failed };

PrecheckResult precheck_transaction(const string& action, const vector<string>& pkgs, bool quiet) {
    if (action != "install" && action != "remove" && action != "purge")
        return PrecheckResult::Proceed;

    if (pkgs.empty()) {
        if (!quiet) cout << "No packages were specified.\n";
        return PrecheckResult::Failed;
    }

    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();

    if (cache == nullptr || dep_cache == nullptr)
        return PrecheckResult::Proceed;

    bool has_changes = false;

    for (const auto& pkg_name : pkgs) {
        pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
        if (pkg.end()) {
            if (!quiet) cout << "Package " << pkg_name << " not found.\n";
            return PrecheckResult::Failed;
        }

        if (action == "install") {
            pkgCache::VerIterator cand = dep_cache->GetCandidateVersion(pkg);
            if (pkg->CurrentVer != 0 && (cand.end() || cand == pkg.CurrentVer())) {
                if (!quiet) cout << pkg_name << " is already the newest version.\n";
                continue;
            }
            has_changes = true;
            continue;
        }

        if (pkg->CurrentVer == 0) {
            if (!quiet) cout << "Package " << pkg_name << " is not installed.\n";
            continue;
        }

        has_changes = true;
    }

    return has_changes ? PrecheckResult::Proceed : PrecheckResult::NoChanges;
}

void mount_fs() {
    exec_argv_devnull_out({"mount", "--bind", "/dev",      TREE_ROOT + "/dev"});
    exec_argv_devnull_out({"mount", "--bind", "/dev/pts",  TREE_ROOT + "/dev/pts"});
    exec_argv_devnull_out({"mount", "--bind", "/proc",     TREE_ROOT + "/proc"});
    exec_argv_devnull_out({"mount", "--bind", "/sys",      TREE_ROOT + "/sys"});

    string resolv_target = TREE_ROOT + "/etc/resolv.conf";
    if (!fs::exists("/etc/resolv.conf")) return;
    error_code ec;
    if (!fs::exists(resolv_target, ec)) {
        ofstream touch(resolv_target);
    }
    exec_argv_devnull_out({"mount", "--bind", "/etc/resolv.conf", resolv_target});
}

void umount_fs() {
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/etc/resolv.conf"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/pts"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/proc"});
    exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/sys"});
}

static string trim_str(const string& s) {
    size_t start = s.find_first_not_of(" \n\r\t<>");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \n\r\t<>");
    return s.substr(start, end - start + 1);
}

static string get_root_device() {
    string out = exec_argv_capture({"findmnt", "-n", "-o", "SOURCE", "/"});
    out = trim_str(out);
    size_t bracket = out.find('[');
    if (bracket != string::npos) out = out.substr(0, bracket);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' '))
        out.pop_back();
    return out;
}

static string get_root_fstype() {
    string out = exec_argv_capture({"findmnt", "-n", "-o", "FSTYPE", "/"});
    return trim_str(out);
}

static string get_vg_name(const string& lv_path) {
    string out = exec_argv_capture({"lvs", "--noheadings", "-o", "vg_name", lv_path});
    return trim_str(out);
}

static bool is_lv_thin(const string& lv_path) {
    string out = exec_argv_capture({"lvs", "--noheadings", "-o", "segtype", lv_path});
    out = trim_str(out);
    return out.find("thin") != string::npos;
}

static double get_vg_free_gb(const string& vg_name) {
    string out = exec_argv_capture({"vgs", "--noheadings", "-o", "vg_free", "--units", "g", vg_name});
    out = trim_str(out);
    size_t g = out.find_first_of("gG");
    if (g != string::npos) out = out.substr(0, g);
    try { return stod(out); } catch (...) { return 0.0; }
}

static string g_cached_root_dev;
static string g_cached_vg_name;

bool manage_sandbox(const string& action) {
    string root_dev = get_root_device();
    string vg_name = get_vg_name(root_dev);
    g_cached_root_dev = root_dev;
    g_cached_vg_name = vg_name;
    string snap_lv_name = "napt_sandbox_snap";
    string snap_dev = "/dev/" + vg_name + "/" + snap_lv_name;

    if (action == "create") {
        umount_fs();
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT});
        exec_argv_devnull_out({"lvremove", "-f", snap_dev});
        exec_argv_devnull_out({"mkdir", "-p", "/nsm/napt"});

        if (root_dev.empty() || vg_name.empty()) {
            cout << "E: Unable to determine the root LVM device or volume group.\n";
            return false;
        }

        bool thin = is_lv_thin(root_dev);
        int rc;
        if (thin) {
            rc = exec_argv_devnull_out({"lvcreate", "-s", "--name", snap_lv_name, "-k", "n", root_dev});
        } else {
            double free_gb = get_vg_free_gb(vg_name);
            if (free_gb < 1.0) {
                cout << "E: Insufficient free space in volume group: 1 GB required, " << free_gb << " GB available.\n";
                return false;
            }
            string snap_size = "1G";
            if (free_gb >= 10.0) snap_size = "5G";
            else if (free_gb >= 5.0) snap_size = "3G";
            else if (free_gb >= 2.0) snap_size = "1.5G";

            rc = exec_argv_devnull_out({"lvcreate", "-L", snap_size, "-s", "--name", snap_lv_name, root_dev});
        }

        if (rc != 0) {
            cout << "E: LVM snapshot of " << root_dev << " failed (exit code " << rc << ").\n";
            return false;
        }

        exec_argv_devnull_out({"lvchange", "-ay", "--ignoreactivationskip", snap_dev});
        exec_argv_devnull_out({"udevadm", "settle"});

        struct stat dev_st;
        bool dev_ready = false;
        for (int attempt = 0; attempt < 50; ++attempt) {
            if (stat(snap_dev.c_str(), &dev_st) == 0 && S_ISBLK(dev_st.st_mode)) { dev_ready = true; break; }
            usleep(100000);
        }

        if (!dev_ready) {
            cout << "E: Snapshot device " << snap_dev << " did not become available in time.\n";
            exec_argv_devnull_out({"lvremove", "-f", snap_dev});
            return false;
        }

        exec_argv_devnull_out({"mkdir", "-p", TREE_ROOT});

        string fstype = get_root_fstype();
        int mount_rc;
        if (fstype == "xfs") {
            mount_rc = exec_argv_devnull_out({"mount", "-t", "xfs", "-o", "nouuid", snap_dev, TREE_ROOT});
        } else if (!fstype.empty()) {
            mount_rc = exec_argv_devnull_out({"mount", "-t", fstype, snap_dev, TREE_ROOT});
        } else {
            mount_rc = exec_argv_devnull_out({"mount", snap_dev, TREE_ROOT});
        }

        if (mount_rc != 0) {
            cout << "E: Unable to mount snapshot at " << TREE_ROOT << " (exit code " << mount_rc << ").\n";
            exec_argv_devnull_out({"lvremove", "-f", snap_dev});
            return false;
        }

        struct stat st;
        if (stat(TREE_ROOT.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            cout << "E: Chroot root " << TREE_ROOT << " was not created.\n";
            return false;
        }

        exec_argv_devnull_out({"mkdir", "-p", TREE_ROOT + "/tmp"});
        sandbox_created_and_mounted.store(true);
        return true;

    } else if (action == "delete") {
        umount_fs();
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT});
        exec_argv_devnull_out({"lvremove", "-f", snap_dev});
        sandbox_created_and_mounted.store(false);
        return true;
    }

    return false;
}

void cleanup_sandbox_on_exit() {
    if (sandbox_created_and_mounted.load()) {
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/etc/resolv.conf"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev/pts"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/dev"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/proc"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT + "/sys"});
        exec_argv_devnull_out({"umount", "-l", TREE_ROOT});

        string vg_name = !g_cached_vg_name.empty() ? g_cached_vg_name : get_vg_name(get_root_device());
        if (!vg_name.empty()) {
            string snap_dev = "/dev/" + vg_name + "/napt_sandbox_snap";
            exec_argv_devnull_out({"lvremove", "-f", snap_dev});
        }
        sandbox_created_and_mounted.store(false);
    }
    global_config_backup.restore_orig();
}

void handle_termination_signal(int sig) {
    (void)sig;
    cleanup_sandbox_on_exit();
    _exit(128 + sig);
}

void setup_safety_handlers() {
    atexit(cleanup_sandbox_on_exit);
    struct sigaction sa;
    sa.sa_handler = handle_termination_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGQUIT, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
}


string get_latest_snapshot(const string& prefix) {
    DIR* dir = opendir(AUTO_SNAP_DIR.c_str());
    if (!dir) return "";
    struct dirent* entry;
    vector<string> matches;
    while ((entry = readdir(dir)) != NULL) {
        string name = entry->d_name;
        if (name.find(prefix) == 0) matches.push_back(name);
    }
    closedir(dir);
    if (matches.empty()) return "";
    sort(matches.begin(), matches.end());
    return matches.back();
}

void do_rollback(const string& prefix) {
    if (!nf_tree_available()) return;
    string root_snap = get_latest_snapshot("root-auto-" + prefix);
    if (!root_snap.empty()) {
        cout << "Rolling back to snapshot: " << root_snap << "\n";
        exec_argv_devnull_out({NF_TREE_BIN, "rollback", root_snap});
    }
}

static std::mutex g_cout_mutex;

string format_bytes(uint64_t bytes);

template<typename... Args>
void safe_log(Args&&... args) {
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    (std::cout << ... << std::forward<Args>(args));
    std::cout << std::flush;
}

string sanitize_filename(const string& raw) {
    size_t pos_slash = raw.find_last_of('/');
    string base = (pos_slash == string::npos) ? raw : raw.substr(pos_slash + 1);
    size_t start = base.find_first_not_of(" \n\r\t");
    string cleaned = (start == string::npos) ? "" : base.substr(start, base.find_last_not_of(" \n\r\t") - start + 1);
    
    string safe;
    safe.reserve(cleaned.size());
    for (char c : cleaned) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-') {
            safe.push_back(c);
        }
    }
    while (!safe.empty() && (safe.front() == '-' || safe.front() == '.')) {
        safe.erase(safe.begin());
    }
    if (safe == "." || safe == "..") safe = "safe_file";
    return safe.empty() ? "safe_file" : safe;
}

string fetch_url(const string& url) {
    if (url.empty()) return "";
    size_t start = url.find_first_not_of(" \n\r\t");
    string norm_url = (start == string::npos) ? "" : url.substr(start, url.find_last_not_of(" \n\r\t") - start + 1);
    if (norm_url.front() == '-') return "";
    return exec_argv_capture({"curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "10", "--max-time", "30", "--", norm_url});
}

string trim_copy(const string& s) {
    size_t start = s.find_first_not_of(" \n\r\t");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \n\r\t");
    return s.substr(start, end - start + 1);
}

bool starts_with(const string& value, const string& prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const string& value, const string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

class NaptAcquireStatus final : public pkgAcquireStatus {
    int fd;
    bool show_host;
    string label;
    int last_shown = -1;
public:
    NaptAcquireStatus(int fd_, bool show_host_, string label_ = "packages")
        : fd(fd_), show_host(show_host_), label(std::move(label_)) {}
    bool MediaChange(string, string) override { return false; }
    bool Pulse(pkgAcquire* owner) override {
        pkgAcquireStatus::Pulse(owner);
        int pct = static_cast<int>(Percent);
        if (fd >= 0) {
            string line = "dlstatus:0:" + to_string(Percent) + ":Downloading\n";
            ssize_t written = write(fd, line.c_str(), line.size());
            (void)written;
        } else if (show_host && pct != last_shown) {
            cout << "\rDownloading " << label << ": " << pct << "%   " << flush;
            last_shown = pct;
        }
        return true;
    }
    void Stop() override {
        pkgAcquireStatus::Stop();
        if (fd < 0 && show_host) cout << "\n";
    }
};

static string local_deb_package_name(const string& path) {
    FileFd fd;
    if (!fd.Open(path, FileFd::ReadOnly)) return "";
    debDebFile deb(fd);
    debDebFile::MemControlExtract extract;
    if (!extract.Read(deb)) return "";
    return extract.Section.FindS("Package");
}

static bool register_local_debs(pkgSourceList* src_list, const vector<string>& targets,
                                 map<string, string>& local_pkg_names, bool quiet) {
    for (const auto& t : targets) {
        if (!ends_with(t, ".deb")) continue;
        string pkg_name = local_deb_package_name(t);
        if (pkg_name.empty()) {
            if (!quiet) cout << "Could not determine package name for " << t << ".\n";
            _error->DumpErrors();
            return false;
        }
        if (!src_list->AddVolatileFile(t)) {
            if (!quiet) cout << "Failed to register local package " << t << ".\n";
            _error->DumpErrors();
            return false;
        }
        local_pkg_names[t] = pkg_name;
    }
    return true;
}

bool run_libapt_transaction(const string& action, const vector<string>& targets,
                             int status_fd, bool quiet) {
    if (status_fd >= 0) _config->Set("APT::Status-Fd", status_fd);
    _config->Set("Dpkg::Use-Pty", "false");

    pkgCacheFile cache_file;
    pkgSourceList* src_list = cache_file.GetSourceList();
    if (src_list == nullptr) { _error->DumpErrors(); return false; }

    map<string, string> local_pkg_names;
    if (!register_local_debs(src_list, targets, local_pkg_names, quiet)) return false;

    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();
    if (cache == nullptr || dep_cache == nullptr) { _error->DumpErrors(); return false; }

    pkgProblemResolver fixer(dep_cache);

    if (action == "install") {
        for (const auto& t : targets) {
            string pkg_name = ends_with(t, ".deb") ? local_pkg_names[t] : t;
            pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
            if (pkg.end()) {
                if (!quiet) cout << "Package " << pkg_name << " not found.\n";
                return false;
            }
            fixer.Clear(pkg);
            fixer.Protect(pkg);
            dep_cache->MarkInstall(pkg, true);
            if (!(*dep_cache)[pkg].Install()) {
                if (!quiet) cout << "Unable to mark " << pkg_name << " for installation.\n";
                _error->DumpErrors();
                return false;
            }
        }
    } else if (action == "remove" || action == "purge") {
        bool purge = (action == "purge");
        for (const auto& pkg_name : targets) {
            pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
            if (pkg.end()) continue;
            fixer.Clear(pkg);
            fixer.Protect(pkg);
            dep_cache->MarkDelete(pkg, purge);
        }
    } else if (action == "upgrade") {
        if (!APT::Upgrade::Upgrade(*dep_cache,
                APT::Upgrade::FORBID_REMOVE_PACKAGES | APT::Upgrade::FORBID_INSTALL_NEW_PACKAGES)) {
            _error->DumpErrors();
            return false;
        }
    } else if (action == "dist-upgrade") {
        if (!APT::Upgrade::Upgrade(*dep_cache, APT::Upgrade::ALLOW_EVERYTHING)) {
            _error->DumpErrors();
            return false;
        }
    } else {
        if (!quiet) cout << "Unknown transaction: " << action << ".\n";
        return false;
    }

    if (!fixer.Resolve(true) || _error->PendingError()) {
        if (!quiet) cout << "Unable to resolve dependencies for this transaction.\n";
        _error->DumpErrors();
        return false;
    }

    unique_ptr<pkgPackageManager> pm(_system->CreatePM(dep_cache));
    if (!pm) { _error->DumpErrors(); return false; }

    pkgAcquire fetcher;
    pkgRecords recs(*cache);

    if (!pm->GetArchives(&fetcher, src_list, &recs) || _error->PendingError()) {
        _error->DumpErrors();
        return false;
    }

    if (!quiet && status_fd < 0) {
        unsigned long long need = fetcher.FetchNeeded();
        if (need > 0) {
            if (need < 1024 * 1024)
                cout << "Downloading packages (" << (need / 1024) << " KB)...\n";
            else
                cout << "Downloading packages (" << (need / 1024 / 1024) << " MB)...\n";
        }
    }

    NaptAcquireStatus acquire_status(status_fd, !quiet && status_fd < 0);
    fetcher.SetLog(&acquire_status);
    if (fetcher.Run() != pkgAcquire::Continue) {
        _error->DumpErrors();
        return false;
    }

    unique_ptr<APT::Progress::PackageManager> pm_progress;
    if (status_fd >= 0)
        pm_progress = make_unique<APT::Progress::PackageManagerProgressFd>(status_fd);
    else
        pm_progress = make_unique<APT::Progress::PackageManager>();

    pkgPackageManager::OrderResult result = pm->DoInstall(pm_progress.get());
    if (result != pkgPackageManager::Completed) {
        _error->DumpErrors();
        return false;
    }

    return true;
}

bool path_is_directory(const string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool path_is_regular_file(const string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

string path_basename(const string& path) {
    size_t pos = path.find_last_of('/');
    if (pos == string::npos) return path;
    return path.substr(pos + 1);
}

string normalize_napt_base_url(const string& raw_url) {
    string url = trim_copy(raw_url);
    if (url.find("http://") != 0 && url.find("https://") != 0)
        url = "https://" + url;
    while (!url.empty() && url.back() == '/') url.pop_back();
    return url;
}

bool is_repo_allowed(const string& url) {
#ifdef allowrepo
    if (normalize_napt_base_url(string(allowrepo)) == normalize_napt_base_url(url))
        return true;
#endif
    ifstream in(NAPT_ALLOWED_FILE);
    if (!in) return false;
    string line;
    string norm_url = normalize_napt_base_url(url);
    while (getline(in, line)) {
        if (normalize_napt_base_url(line) == norm_url) return true;
    }
    return false;
}

void print_napt_repo_warning(const string& url) {
    if (is_repo_allowed(url)) return;
    static set<string> warned_repos;
    if (warned_repos.count(url)) return;
    warned_repos.insert(url);
    cout << "W: Repository not authenticated: " << url << "\n"
         << "W: Packages originating from this source are unverified and may pose a security risk.\n"
         << "W: Proceed only if this repository is trusted.\n";
}

bool parse_napt_source_line(const string& raw_line, NaptSource& source) {
    string line = trim_copy(raw_line);
    if (line.empty() || line[0] == '#') return false;
    istringstream iss(line);
    string type, base_url, release;
    if (!(iss >> type >> base_url >> release)) return false;
    if (type != "deb") return false;
    base_url = normalize_napt_base_url(base_url);
    release = trim_copy(release);
    if (base_url.empty() || release.empty()) return false;
    source.base_url = base_url;
    source.release = release;
    return true;
}

void load_napt_sources_from_file(const string& path, vector<NaptSource>& sources) {
    ifstream in(path);
    if (!in) return;
    string line;
    while (getline(in, line)) {
        NaptSource source;
        if (parse_napt_source_line(line, source)) sources.push_back(source);
    }
}

vector<NaptSource> load_napt_sources() {
    vector<NaptSource> sources;

    if (path_is_regular_file(NAPT_SOURCES_FILE))
        load_napt_sources_from_file(NAPT_SOURCES_FILE, sources);

    if (path_is_directory(NAPT_SOURCES_DIR)) {
        DIR* dir = opendir(NAPT_SOURCES_DIR.c_str());
        if (dir != nullptr) {
            vector<string> files;
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                string name = entry->d_name;
                if (name == "." || name == "..") continue;
                string path = NAPT_SOURCES_DIR + "/" + name;
                if (path_is_regular_file(path)) files.push_back(path);
            }
            closedir(dir);
            sort(files.begin(), files.end());
            for (const auto& path : files) load_napt_sources_from_file(path, sources);
        }
    }

    return sources;
}

bool write_text_file(const string& path, const string& content) {
    static std::atomic<uint64_t> seq{0};
    string tmp_path = path + ".tmp." + to_string(getpid()) + "_" + to_string(seq.fetch_add(1));
    {
        ofstream out(tmp_path, ios::out | ios::trunc);
        if (!out) return false;
        out << content;
        out.flush();
        if (!out.good()) {
            unlink(tmp_path.c_str());
            return false;
        }
    }
    if (rename(tmp_path.c_str(), path.c_str()) != 0) {
        unlink(tmp_path.c_str());
        return false;
    }
    return true;
}

bool read_text_file(const string& path, string& content) {
    ifstream in(path);
    if (!in) return false;
    stringstream buffer;
    buffer << in.rdbuf();
    content = buffer.str();
    return true;
}

bool parse_napt_repo_metadata(const string& text, NaptRepoMetadata& metadata) {
    metadata.packages.clear();
    metadata.required_packages.clear();
    metadata.replaces.clear();
    string line;
    bool in_packages = false;
    bool in_required = false;
    bool in_replaces = false;
    stringstream ss(text);
    while (getline(ss, line)) {
        string trimmed = trim_copy(line);
        if (trimmed.empty() || trimmed == "[napt repository]") continue;
        if (starts_with(trimmed, "release=")) {
            metadata.release = trim_copy(trimmed.substr(8));
            continue;
        }
        if (trimmed == "packages:") { in_packages = true; in_required = false; in_replaces = false; continue; }
        if (trimmed == "required:") { in_required = true; in_packages = false; in_replaces = false; continue; }
        if (trimmed == "replaces:") { in_replaces = true; in_packages = false; in_required = false; continue; }

        if (in_required) {
            size_t start = trimmed.find('{');
            size_t end = trimmed.find('}');
            if (start != string::npos && end != string::npos && end > start) {
                string req_pkg = trim_copy(trimmed.substr(start + 1, end - start - 1));
                if (!req_pkg.empty()) metadata.required_packages.push_back(req_pkg);
            }
            continue;
        }

        if (in_replaces) {
            size_t pos = trimmed.find('=');
            if (pos != string::npos) {
                string orig_pkg = trim_copy(trimmed.substr(0, pos));
                string rep_pkg = trim_copy(trimmed.substr(pos + 1));
                if (!orig_pkg.empty() && !rep_pkg.empty()) {
                    metadata.replaces[orig_pkg] = rep_pkg;
                }
            }
            continue;
        }

        if (in_packages) {
            size_t pos = trimmed.find('=');
            if (pos == string::npos) continue;
            string pkg = trim_copy(trimmed.substr(0, pos));
            string rest = trim_copy(trimmed.substr(pos + 1));
            string file_name, hash;

            size_t rep_pos = rest.find("replaces=");
            if (rep_pos != string::npos) {
                string rep_str = rest.substr(rep_pos + 9);
                size_t rep_end = rep_str.find_first_of(" \t");
                if (rep_end != string::npos) {
                    rep_str = rep_str.substr(0, rep_end);
                }
                stringstream rep_ss(rep_str);
                string rep_item;
                while (getline(rep_ss, rep_item, ',')) {
                    string clean_item = trim_copy(rep_item);
                    if (!clean_item.empty()) {
                        metadata.replaces[clean_item] = pkg;
                    }
                }
                size_t remove_len = (rep_end != string::npos) ? (9 + rep_end) : string::npos;
                rest = trim_copy(rest.substr(0, rep_pos) + " " + (remove_len != string::npos ? rest.substr(rep_pos + remove_len) : ""));
            }

            size_t sha_pos = rest.find("sha256=");
            if (sha_pos != string::npos) {
                string sha_str = rest.substr(sha_pos + 7);
                size_t sha_end = sha_str.find_first_of(" \t");
                if (sha_end != string::npos) {
                    hash = trim_copy(sha_str.substr(0, sha_end));
                } else {
                    hash = trim_copy(sha_str);
                }
                file_name = trim_copy(rest.substr(0, sha_pos));
            } else {
                file_name = rest;
            }
            if (!pkg.empty() && !file_name.empty())
                metadata.packages[pkg] = {file_name, hash};
        }
    }
    return !metadata.release.empty();
}

bool sync_napt_metadata() {
    vector<NaptSource> sources = load_napt_sources();
    if (sources.empty()) return true;

    exec_argv_devnull_out({"mkdir", "-p", NAPT_ETC_DIR});

    vector<future<bool>> futures;
    futures.reserve(sources.size());

    for (const auto& source : sources) {
        futures.push_back(std::async(std::launch::async, [source]() -> bool {
            print_napt_repo_warning(source.base_url);
            string url = source.base_url + "/releases/" + source.release + "/repo-metadata";
            string metadata = fetch_url(url);
            if (metadata.empty()) {
                safe_log("Failed to fetch metadata: ", url, "\n");
                return false;
            }
            string safe_release = sanitize_filename(source.release);
            string release_dir = NAPT_ETC_DIR + "/" + safe_release;
            if (exec_argv_devnull_out({"mkdir", "-p", release_dir}) != 0) {
                safe_log("Failed to create metadata directory: ", release_dir, "\n");
                return false;
            }
            string output_path = release_dir + "/repo-metadata";
            if (!write_text_file(output_path, metadata)) {
                safe_log("Failed to write metadata: ", output_path, "\n");
                return false;
            }
            safe_log("Synced metadata for ", source.release, " (", format_bytes(metadata.size()), ") from ", source.base_url, "\n");
            return true;
        }));
    }

    bool ok = true;
    for (auto& fut : futures) {
        if (!fut.get()) ok = false;
    }
    return ok;
}

bool clean_napt_cache() {
    error_code ec;
    if (!fs::exists(NAPT_CACHE_DIR, ec)) {
        if (!fs::create_directories(NAPT_CACHE_DIR, ec)) {
            cout << "Failed to create cache directory: " << NAPT_CACHE_DIR << "\n";
            return false;
        }
        cout << "Cache is already clean.\n";
        return true;
    }

    bool removed_any = false;
    for (const auto& entry : fs::directory_iterator(NAPT_CACHE_DIR, ec)) {
        if (ec) {
            cout << "Failed to read cache directory: " << NAPT_CACHE_DIR << "\n";
            return false;
        }
        fs::remove_all(entry.path(), ec);
        if (ec) {
            cout << "Failed to remove: " << entry.path().string() << "\n";
            return false;
        }
        removed_any = true;
    }

    if (!fs::exists(NAPT_CACHE_DIR, ec) && !fs::create_directories(NAPT_CACHE_DIR, ec)) {
        cout << "Failed to recreate cache directory: " << NAPT_CACHE_DIR << "\n";
        return false;
    }

    if (removed_any)
        cout << "Cache cleaned: " << NAPT_CACHE_DIR << "\n";
    else
        cout << "Cache is already clean.\n";

    return true;
}

string format_bytes(uint64_t bytes) {
    if (bytes < 1024) return to_string(bytes) + " B";
    if (bytes < 1024 * 1024) {
        double kb = static_cast<double>(bytes) / 1024.0;
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f KB", kb);
        return string(buf);
    }
    if (bytes < 1024 * 1024 * 1024) {
        double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
        char buf[32];
        snprintf(buf, sizeof(buf), "%.2f MB", mb);
        return string(buf);
    }
    double gb = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f GB", gb);
    return string(buf);
}

class TerminalProgressBar {
public:
    static string render(int percentage, const string& action_label, const string& extra_stats = "", int bar_width = 22) {
        if (percentage < 0) percentage = 0;
        if (percentage > 100) percentage = 100;

        int filled = (percentage * bar_width) / 100;
        int empty = bar_width - filled;

        string bar;
        for (int i = 0; i < filled; ++i) bar += "\u2588";
        for (int i = 0; i < empty; ++i)  bar += "\u2591";

        string cyan_bold = "\033[1;36m";
        string green = "\033[38;2;52;211;153m";
        string gray = "\033[38;2;148;163;184m";
        string reset = "\033[0m";

        ostringstream oss;
        char pct_buf[16];
        snprintf(pct_buf, sizeof(pct_buf), "%3d%%", percentage);
        oss << "\r " << cyan_bold << pct_buf << reset << " ["
            << green << bar << reset << "] "
            << action_label;
        if (!extra_stats.empty()) {
            oss << " " << gray << "(" << extra_stats << ")" << reset;
        }
        oss << "   ";
        return oss.str();
    }
};

class ETAEstimator {
    chrono::steady_clock::time_point start_time;
public:
    ETAEstimator() : start_time(chrono::steady_clock::now()) {}

    void reset() {
        start_time = chrono::steady_clock::now();
    }

    string get_stats(int current_percent) {
        if (current_percent <= 0) return "Calculating...";
        auto now = chrono::steady_clock::now();
        double elapsed_sec = chrono::duration_cast<chrono::duration<double>>(now - start_time).count();
        if (elapsed_sec < 0.25) return "Estimating...";

        double pct_per_sec = static_cast<double>(current_percent) / elapsed_sec;
        if (pct_per_sec <= 0.001) return "Calculating...";

        double remaining_pct = 100.0 - current_percent;
        double remaining_sec = remaining_pct / pct_per_sec;

        int mins = static_cast<int>(remaining_sec) / 60;
        int secs = static_cast<int>(remaining_sec) % 60;

        char buf[64];
        snprintf(buf, sizeof(buf), "ETA: %02d:%02d", mins, secs);
        return string(buf);
    }
};

vector<NaptRepoMetadata> load_cached_napt_metadata();

bool autoclean_napt_cache() {
    error_code ec;
    if (!fs::exists(NAPT_CACHE_DIR, ec)) {
        cout << "Cache directory does not exist: " << NAPT_CACHE_DIR << "\n";
        return true;
    }

    vector<NaptRepoMetadata> repos = load_cached_napt_metadata();
    set<string> valid_filenames;
    for (const auto& repo : repos) {
        for (const auto& entry : repo.packages) {
            valid_filenames.insert(path_basename(entry.second.first));
        }
    }

    bool removed_any = false;
    uint64_t bytes_freed = 0;

    for (const auto& rel_entry : fs::directory_iterator(NAPT_CACHE_DIR, ec)) {
        if (!rel_entry.is_directory()) continue;
        for (const auto& file_entry : fs::directory_iterator(rel_entry.path(), ec)) {
            if (!file_entry.is_regular_file()) continue;
            string filename = file_entry.path().filename().string();
            if (valid_filenames.find(filename) == valid_filenames.end()) {
                uint64_t sz = file_entry.file_size(ec);
                if (!ec) bytes_freed += sz;
                fs::remove(file_entry.path(), ec);
                if (!ec) {
                    cout << "Autoclean removed stale package: " << filename << "\n";
                    removed_any = true;
                }
            }
        }
    }

    if (removed_any) {
        cout << "Autoclean finished. Space freed: " << format_bytes(bytes_freed) << "\n";
    } else {
        cout << "Cache is already clean. No obsolete packages found.\n";
    }
    return true;
}

void print_install_already_present_message(const string& pkg_name, bool is_upgrade) {
    if (is_upgrade) {
        cout << pkg_name << " is already up to date.\n";
        return;
    }
    cout << pkg_name << " is already installed. To upgrade it, run napt upgrade "
         << pkg_name << ", or napt upgrade with no arguments to upgrade all packages.\n"
         << "For large transactions, --apply-host skips the chroot verification step.\n";
}

vector<NaptRepoMetadata> load_cached_napt_metadata() {
    vector<NaptRepoMetadata> repos;
    vector<NaptSource> sources = load_napt_sources();
    for (const auto& source : sources) {
        string path = NAPT_ETC_DIR + "/" + sanitize_filename(source.release) + "/repo-metadata";
        string content;
        if (!read_text_file(path, content)) continue;
        NaptRepoMetadata metadata;
        metadata.base_url = source.base_url;
        metadata.release = source.release;
        if (!parse_napt_repo_metadata(content, metadata)) continue;
        if (metadata.release.empty()) metadata.release = source.release;
        repos.push_back(metadata);
    }
    return repos;
}

int compare_versions(const string& a, const string& b) {
    if (a.empty() && b.empty()) return 0;
    if (a.empty()) return -1;
    if (b.empty()) return 1;
    if (_system != nullptr && _system->VS != nullptr)
        return _system->VS->CmpVersion(a.c_str(), b.c_str());
    if (a == b) return 0;
    return a < b ? -1 : 1;
}

string extract_napt_version(const string& pkg_name, const string& file_name) {
    string base = path_basename(trim_copy(file_name));
    if (!ends_with(base, ".deb")) return "";
    string stem = base.substr(0, base.size() - 4);
    string rest;
    if (starts_with(stem, pkg_name + "_"))
        rest = stem.substr(pkg_name.size() + 1);
    else if (starts_with(stem, pkg_name + "-"))
        rest = stem.substr(pkg_name.size() + 1);
    else
        return "";
    size_t split = rest.find_last_of('_');
    if (split != string::npos && split > 0) return rest.substr(0, split);
    split = rest.find_last_of('-');
    if (split != string::npos && split > 0) return rest.substr(0, split);
    return rest;
}

AptPackageState get_apt_package_state(pkgCacheFile& cache_file, const string& pkg_name) {
    AptPackageState state;
    pkgCache* cache = cache_file.GetPkgCache();
    pkgDepCache* dep_cache = cache_file.GetDepCache();
    if (cache == nullptr || dep_cache == nullptr) return state;
    pkgCache::PkgIterator pkg = cache->FindPkg(pkg_name);
    if (pkg.end()) return state;
    state.found = true;
    if (pkg->CurrentVer != 0) {
        state.installed = true;
        state.installed_version = pkg.CurrentVer().VerStr();
    }
    pkgCache::VerIterator cand = dep_cache->GetCandidateVersion(pkg);
    if (!cand.end()) state.candidate_version = cand.VerStr();
    return state;
}

NaptPackageCandidate find_best_napt_candidate(const vector<NaptRepoMetadata>& repos, const string& pkg_name) {
    NaptPackageCandidate best;

    // 1. Direct package match
    for (const auto& repo : repos) {
        auto it = repo.packages.find(pkg_name);
        if (it == repo.packages.end()) continue;
        NaptPackageCandidate candidate;
        candidate.found = true;
        candidate.base_url = repo.base_url;
        candidate.release = repo.release;
        candidate.file_name = it->second.first;
        candidate.sha256 = it->second.second;
        candidate.actual_pkg_name = pkg_name;
        candidate.original_query_name = pkg_name;
        candidate.is_replacement = false;
        candidate.version = extract_napt_version(pkg_name, candidate.file_name);
        if (!best.found || compare_versions(candidate.version, best.version) > 0)
            best = candidate;
    }
    if (best.found) return best;

    // 2. Replaces match (alias / replacement redirection)
    for (const auto& repo : repos) {
        auto rep_it = repo.replaces.find(pkg_name);
        if (rep_it == repo.replaces.end()) continue;

        string target_napt_pkg = rep_it->second;
        auto it = repo.packages.find(target_napt_pkg);
        if (it == repo.packages.end()) continue;

        NaptPackageCandidate candidate;
        candidate.found = true;
        candidate.base_url = repo.base_url;
        candidate.release = repo.release;
        candidate.file_name = it->second.first;
        candidate.sha256 = it->second.second;
        candidate.actual_pkg_name = target_napt_pkg;
        candidate.original_query_name = pkg_name;
        candidate.is_replacement = true;
        candidate.version = extract_napt_version(target_napt_pkg, candidate.file_name);
        if (!best.found || compare_versions(candidate.version, best.version) > 0)
            best = candidate;
    }

    return best;
}

string build_napt_download_url(const NaptPackageCandidate& candidate) {
    string file_name = trim_copy(candidate.file_name);
    while (!file_name.empty() && file_name.front() == '/') file_name.erase(file_name.begin());
    return candidate.base_url + "/releases/" + candidate.release + "/" + file_name;
}

bool cache_napt_package(const NaptPackageCandidate& candidate, string& local_path) {
    string safe_release = sanitize_filename(candidate.release);
    string safe_file = sanitize_filename(candidate.file_name);
    string release_dir = NAPT_CACHE_DIR + "/" + safe_release;
    if (exec_argv_devnull_out({"mkdir", "-p", release_dir}) != 0) return false;
    local_path = release_dir + "/" + safe_file;
    string url = build_napt_download_url(candidate);
    if (url.empty() || url.front() == '-') return false;
    return exec_argv_devnull_out({"curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https", "-o", local_path, "--", url}) == 0;
}

string calculate_sha256(const string& file_path) {
    string out = exec_argv_capture({"sha256sum", file_path});
    size_t space_pos = out.find(' ');
    if (space_pos != string::npos) return out.substr(0, space_pos);
    return trim_copy(out);
}

struct PendingNaptDownload {
    string pkg_name;
    NaptPackageCandidate candidate;
    string local_path;
    bool success = false;
    string error_msg;
};

static bool download_napt_packages(vector<PendingNaptDownload>& pending_napt_downloads, vector<InstallDecision>& decisions, bool quiet) {
    if (pending_napt_downloads.empty()) return true;

    size_t num_threads = std::min<size_t>(4, pending_napt_downloads.size());
    vector<thread> workers;
    std::atomic<size_t> current_index(0);

    for (size_t t = 0; t < num_threads; ++t) {
        workers.emplace_back([&]() {
            while (true) {
                size_t idx = current_index.fetch_add(1);
                if (idx >= pending_napt_downloads.size()) break;

                auto& pending = pending_napt_downloads[idx];
                if (!quiet) safe_log("Downloading Napt package: ", pending.pkg_name, "...\n");
                auto start_time = chrono::steady_clock::now();
                if (!cache_napt_package(pending.candidate, pending.local_path)) {
                    pending.error_msg = "E: Failed to download " + pending.pkg_name + " from the Napt repository.";
                    continue;
                }
                auto end_time = chrono::steady_clock::now();
                double elapsed_sec = chrono::duration_cast<chrono::duration<double>>(end_time - start_time).count();

                if (pending.candidate.sha256.empty()) {
                    pending.error_msg = "E: SHA256 checksum is missing in metadata for package " + pending.pkg_name + ".\nE: Refusing to install unverified package.";
                    exec_argv_devnull_out({"rm", "-f", pending.local_path});
                    continue;
                }

                string local_hash = calculate_sha256(pending.local_path);
                if (local_hash != pending.candidate.sha256) {
                    pending.error_msg = "E: SHA256 checksum mismatch for " + pending.pkg_name + ".\nE: Expected: " + pending.candidate.sha256 + "\nE: Got:      " + local_hash + "\nE: Aborting installation of this package.";
                    exec_argv_devnull_out({"rm", "-f", pending.local_path});
                    continue;
                }

                error_code ec;
                uint64_t file_sz = fs::file_size(pending.local_path, ec);
                string sz_str = (!ec && file_sz > 0) ? format_bytes(file_sz) : "";
                string speed_str = "";
                if (!ec && file_sz > 0 && elapsed_sec > 0.005) {
                    double bytes_per_sec = static_cast<double>(file_sz) / elapsed_sec;
                    speed_str = format_bytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
                }

                if (!quiet) {
                    string checkmark = "\033[1;32m✔\033[0m";
                    string cyan = "\033[1;36m";
                    string gray = "\033[38;2;148;163;184m";
                    string reset = "\033[0m";
                    string details = "";
                    if (!sz_str.empty()) details += sz_str;
                    if (!speed_str.empty()) details += (details.empty() ? "" : " | ") + speed_str;

                    safe_log(" ", checkmark, " ", cyan, pending.pkg_name, reset,
                             (!details.empty() ? " " + gray + "(" + details + ")" + reset : ""),
                             "\n");
                }
                pending.success = true;
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    bool ok = true;
    for (const auto& pending : pending_napt_downloads) {
        if (!pending.success) {
            if (!quiet) safe_log(pending.error_msg, "\n");
            ok = false;
        } else {
            InstallDecision decision;
            decision.package_name     = pending.candidate.actual_pkg_name.empty() ? pending.pkg_name : pending.candidate.actual_pkg_name;
            decision.apt_argument     = pending.local_path;
            decision.selected_version = pending.candidate.version;
            decision.from_napt        = true;
            decisions.push_back(decision);
            if (!quiet) {
                if (pending.candidate.is_replacement) {
                    safe_log("Selected ", pending.candidate.actual_pkg_name, 
                             (!pending.candidate.version.empty() ? " (" + pending.candidate.version + ")" : ""),
                             " from the Napt repository (replacing ", pending.pkg_name, ").\n");
                } else {
                    safe_log("Selected ", pending.pkg_name, 
                             (!pending.candidate.version.empty() ? " (" + pending.candidate.version + ")" : ""),
                             " from the Napt repository.\n");
                }
            }
        }
    }
    return ok;
}

bool resolve_install_decisions(const vector<string>& pkgs, vector<InstallDecision>& decisions, bool quiet, bool is_upgrade = false) {
    if (pkgs.empty()) {
        if (!quiet) cout << "E: No packages were specified.\n";
        return false;
    }

    pkgCacheFile cache_file;
    vector<NaptRepoMetadata> repos = load_cached_napt_metadata();
    bool had_error = false;
    vector<PendingNaptDownload> pending_napt_downloads;

    for (const auto& pkg_name : pkgs) {
        if (ends_with(pkg_name, ".deb")) {
            if (!path_is_regular_file(pkg_name)) {
                if (!quiet) cout << "E: Unable to locate local package file: " << pkg_name << ".\n";
                had_error = true;
                continue;
            }
            error_code ec;
            fs::path abs_path = fs::absolute(pkg_name, ec);
            if (!ec) abs_path = fs::weakly_canonical(abs_path, ec);
            string resolved_path = ec ? pkg_name : abs_path.string();

            if (!quiet) cout << "Selecting local package archive: " << resolved_path << ".\n";
            InstallDecision decision;
            decision.package_name     = resolved_path;
            decision.apt_argument     = resolved_path;
            decision.selected_version = "";
            decision.from_napt        = false;
            decisions.push_back(decision);
            continue;
        }

        AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
        NaptPackageCandidate napt_candidate = find_best_napt_candidate(repos, pkg_name);

        if (!apt_state.found && !napt_candidate.found) {
            if (!quiet) cout << "E: Unable to locate package " << pkg_name << ".\n";
            had_error = true;
            continue;
        }

        bool use_napt = false;
        if (napt_candidate.found) {
            if (napt_candidate.is_replacement) {
                use_napt = true;
                if (!quiet) {
                    cout << "Note: Package '" << pkg_name << "' is replaced by Napt package '" 
                         << napt_candidate.actual_pkg_name << "' (replaces rule). Redirecting...\n";
                }
            } else if (!apt_state.found || apt_state.candidate_version.empty()) {
                use_napt = true;
            } else if (compare_versions(napt_candidate.version, apt_state.candidate_version) > 0) {
                use_napt = true;
            }
        }

        if (use_napt) {
            print_napt_repo_warning(napt_candidate.base_url);
            AptPackageState target_apt_state = (napt_candidate.is_replacement)
                ? get_apt_package_state(cache_file, napt_candidate.actual_pkg_name)
                : apt_state;

            if (target_apt_state.installed && compare_versions(target_apt_state.installed_version, napt_candidate.version) >= 0) {
                if (!quiet) print_install_already_present_message(napt_candidate.actual_pkg_name, is_upgrade);
                continue;
            }
            pending_napt_downloads.push_back({pkg_name, napt_candidate, "", false, ""});
            continue;
        }

        if (!apt_state.found || apt_state.candidate_version.empty()) {
            if (!quiet) cout << "E: Unable to locate package " << pkg_name << ".\n";
            had_error = true;
            continue;
        }

        if (apt_state.installed && compare_versions(apt_state.installed_version, apt_state.candidate_version) >= 0) {
            if (!quiet) print_install_already_present_message(pkg_name, is_upgrade);
            continue;
        }

        InstallDecision decision;
        decision.package_name     = pkg_name;
        decision.apt_argument     = pkg_name;
        decision.selected_version = apt_state.candidate_version;
        decision.from_napt        = false;
        decisions.push_back(decision);
        if (!quiet) {
            cout << "Selected " << pkg_name;
            if (!apt_state.candidate_version.empty()) cout << " (" << apt_state.candidate_version << ")";
            cout << " from the Debian archive.\n";
        }
    }

    if (!download_napt_packages(pending_napt_downloads, decisions, quiet)) {
        had_error = true;
    }

    return !had_error;
}

void do_nflinux_upgrade(bool apply_host) {
    (void)apply_host;
#ifdef nflinux
    global_config_backup.backup();

    string os_release = fetch_url("https://nextferret.github.io/etc/os-release");
    string codenames = fetch_url("https://nextferret.github.io/version_codename");
    string repo_number_str = trim_copy(fetch_url("https://nextferret.github.io/repo-number"));
    string napt_sources = "";
    string apt_sources = "";

    if (!codenames.empty() && !repo_number_str.empty()) {
        size_t comma = codenames.find(',');
        if (comma != string::npos) {
            string napt_code = trim_copy(codenames.substr(0, comma));
            string debian_code = trim_copy(codenames.substr(comma + 1));
            string base_repo_url = "https://nextferretdur.github.io/repo-nflinux-" + repo_number_str;
            string meta_url = base_repo_url + "/releases/" + napt_code + "/repo-metadata";
            if (!fetch_url(meta_url).empty()) {
                napt_sources = "deb " + base_repo_url + " " + napt_code + "\n";
                apt_sources = "deb http://deb.debian.org/debian " + debian_code + " main contrib non-free non-free-firmware\n";
                apt_sources += "deb http://deb.debian.org/debian-security " + debian_code + "-security main contrib non-free non-free-firmware\n";
                apt_sources += "deb http://deb.debian.org/debian " + debian_code + "-updates main contrib non-free non-free-firmware\n";
            }
        }
    }

    if (!os_release.empty() || !apt_sources.empty() || !napt_sources.empty()) {
        global_config_backup.set_new(os_release, apt_sources, napt_sources);
        global_config_backup.apply_new();
    }

    vector<NaptRepoMetadata> repos = load_cached_napt_metadata();
    vector<string> pkgs_to_install;
    for (const auto& repo : repos) {
        for (const auto& req : repo.required_packages)
            pkgs_to_install.push_back(req);
    }

    if (!pkgs_to_install.empty()) {
        sort(pkgs_to_install.begin(), pkgs_to_install.end());
        pkgs_to_install.erase(unique(pkgs_to_install.begin(), pkgs_to_install.end()), pkgs_to_install.end());
        cout << "Installing required packages from repositories...\n";
        perform_install_transaction(pkgs_to_install, apply_host);
    }
#endif
}

vector<string> bind_mount_local_deb_dirs(const vector<string>& targets) {
    set<string> parents;
    for (const auto& t : targets) {
        if (!ends_with(t, ".deb")) continue;
        fs::path parent = fs::path(t).parent_path();
        if (!parent.empty()) parents.insert(parent.string());
    }

    vector<string> mounted;
    for (const auto& parent : parents) {
        string target = TREE_ROOT + parent;
        error_code ec;
        fs::create_directories(target, ec);
        if (ec) continue;
        exec_argv_devnull_out({"mount", "--bind", parent, target});
        mounted.push_back(target);
    }
    return mounted;
}

void unbind_local_deb_dirs(const vector<string>& mounted) {
    for (auto it = mounted.rbegin(); it != mounted.rend(); ++it)
        exec_argv_devnull_out({"umount", "-l", *it});
}

void perform_transaction_argv(const string& action, const vector<string>& targets, bool apply_host) {
    if (!apply_host) {
        if (!manage_sandbox("create")) {
            cout << "Aborting transaction: chroot could not be created.\n";
            return;
        }
        mount_fs();
        vector<string> local_deb_mounts = bind_mount_local_deb_dirs(targets);

        int apt_pipe[2]  = {-1, -1};
        bool have_pipe   = (pipe(apt_pipe) == 0);
        int err_pipe[2]  = {-1, -1};
        bool have_err    = (pipe2(err_pipe, O_CLOEXEC) == 0);

        cout.flush();
        cerr.flush();
        pid_t pid = fork();
        if (pid == 0) {
            if (chroot(TREE_ROOT.c_str()) != 0 || chdir("/") != 0) {
                if (have_err) {
                    const char* msg = "chroot/chdir failed\n";
                    ssize_t written = write(err_pipe[1], msg, strlen(msg));
                    (void)written;
                }
                _exit(1);
            }

            if (g_enable_seccomp) {
                string seccomp_err;
                if (!ChrootSeccompManager::apply_filter(seccomp_err)) {
                    if (have_err && !seccomp_err.empty()) {
                        string msg = "W: SECCOMP filter notice: " + seccomp_err + "\n";
                        ssize_t written = write(err_pipe[1], msg.c_str(), msg.size());
                        (void)written;
                    }
                }
            }

            int devnull_r = open("/dev/null", O_RDONLY);
            if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }

            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }

            if (have_err) {
                close(err_pipe[0]);
                if (err_pipe[1] != STDERR_FILENO) {
                    dup2(err_pipe[1], STDERR_FILENO);
                    close(err_pipe[1]);
                }
            } else {
                int dn2 = open("/dev/null", O_WRONLY);
                if (dn2 >= 0) { dup2(dn2, STDERR_FILENO); close(dn2); }
            }

            int status_fd = -1;
            if (have_pipe) {
                close(apt_pipe[0]);
                if (apt_pipe[1] != 3) { dup2(apt_pipe[1], 3); close(apt_pipe[1]); }
                fcntl(3, F_SETFD, 0);
                status_fd = 3;
            }

            for (int fd = 4; fd < 1024; ++fd) close(fd);

            pkgInitConfig(*_config);
            pkgInitSystem(*_config, _system);

            setenv("DEBIAN_FRONTEND", "noninteractive", 1);
            bool ok = run_libapt_transaction(action, targets, status_fd, true);
            cout.flush();
            cerr.flush();
            _exit(ok ? 0 : 1);

        } else if (pid > 0) {
            if (have_pipe) close(apt_pipe[1]);
            if (have_err)  close(err_pipe[1]);

            cout << "\033[1;36m==>\033[0m Verifying transaction in isolated sandbox"
                 << (g_enable_seccomp ? " (SECCOMP BPF active)...\n" : "...\n");

            std::atomic<int> apt_percent(-1);
            string child_stderr_output;
            ETAEstimator chroot_eta;

            std::thread stderr_reader([&]() {
                if (!have_err) return;
                char buf[256];
                ssize_t n;
                while ((n = read(err_pipe[0], buf, sizeof(buf) - 1)) > 0) {
                    buf[n] = '\0';
                    child_stderr_output += buf;
                }
                close(err_pipe[0]);
            });

            std::thread reader_thread([&]() {
                if (!have_pipe) return;
                FILE* f = fdopen(apt_pipe[0], "r");
                if (!f) { close(apt_pipe[0]); return; }
                char line[512];
                int last_shown = -1;
                while (fgets(line, sizeof(line), f) != NULL) {
                    string s(line);
                    bool is_pm = (s.size() > 9 && s.substr(0, 9) == "pmstatus:");
                    bool is_dl = (!is_pm && s.size() > 9 && s.substr(0, 9) == "dlstatus:");
                    if (!is_pm && !is_dl) continue;
                    size_t c1 = s.find(':');
                    if (c1 == string::npos) continue;
                    size_t c2 = s.find(':', c1 + 1);
                    if (c2 == string::npos) continue;
                    size_t c3 = s.find(':', c2 + 1);
                    if (c3 == string::npos) continue;
                    string pct_str = s.substr(c2 + 1, c3 - c2 - 1);
                    try {
                        int pct = static_cast<int>(stod(pct_str));
                        if (pct > apt_percent.load()) apt_percent.store(pct);
                        int current = apt_percent.load();
                        if (current != last_shown) {
                            cout << TerminalProgressBar::render(current, "Sandbox Verification", chroot_eta.get_stats(current)) << flush;
                            last_shown = current;
                        }
                    } catch (...) {}
                }
                fclose(f);
            });

            int status = 0;
            bool waited = wait_for_child(pid, status);

            reader_thread.join();
            stderr_reader.join();

            unbind_local_deb_dirs(local_deb_mounts);
            umount_fs();
            manage_sandbox("delete");

            if (!waited) {
                global_config_backup.restore_orig();
                cout << "\n\033[1;31mE:\033[0m Chroot verification interrupted.\n";
                return;
            }
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                global_config_backup.restore_orig();
                cout << "\n\033[1;31mE:\033[0m Chroot verification failed.\n";
                if (!child_stderr_output.empty()) {
                    cout << "---- chroot error output ----\n" << child_stderr_output;
                    if (child_stderr_output.back() != '\n') cout << '\n';
                    cout << "------------------------------\n";
                }
                return;
            }

            cout << TerminalProgressBar::render(100, "Sandbox Verification Successful", "Completed") << "\n\n";

            if (!assume_yes) {
                cout << "\033[1;32m✔\033[0m Sandbox verification passed without errors.\n";
                cout << "The transaction is now ready to be applied to the host system.\n";
                cout << "Do you wish to continue? Type 'yes' to confirm, or press Enter to abort: ";
                string confirm;
                getline(cin, confirm);
                if (confirm != "yes" && confirm != "YES") {
                    global_config_backup.restore_orig();
                    cout << "Transaction aborted by user.\n";
                    return;
                }
            }
        } else {
            if (have_pipe) { close(apt_pipe[0]); close(apt_pipe[1]); }
            if (have_err)  { close(err_pipe[0]); close(err_pipe[1]); }
            cout << "\033[1;31mE:\033[0m Unable to fork process for chroot verification.\n";
            return;
        }
    }

    global_config_backup.restore_orig();
    bool snapshot_created = create_snapshot("apt-pre");
    global_config_backup.apply_new();

    // Preserve active kernel modules in case of kernel upgrades
    string kver = trim_copy(exec_argv_capture({"uname", "-r"}));
    if (!kver.empty()) {
        string src = "/lib/modules/" + kver;
        string dst = "/var/tmp/.arvor_kmodules_" + kver;
        error_code ec;
        if (fs::exists(src, ec) && !fs::exists(dst, ec)) {
            exec_argv_devnull_out({"cp", "-a", src, dst});
        }
    }

    cout.flush();
    cerr.flush();

    cout << "\033[1;36m==>\033[0m Applying transaction to the host system...\n";

    int host_pipe[2];
    bool have_host_pipe = (pipe(host_pipe) == 0);

    pid_t host_pid = fork();
    if (host_pid == 0) {
        int devnull_r = open("/dev/null", O_RDONLY);
        if (devnull_r >= 0) { dup2(devnull_r, STDIN_FILENO); close(devnull_r); }

        int status_fd = -1;
        if (have_host_pipe) {
            close(host_pipe[0]);
            if (host_pipe[1] != 3) { dup2(host_pipe[1], 3); close(host_pipe[1]); }
            fcntl(3, F_SETFD, 0);
            status_fd = 3;
        }

        for (int fd = 4; fd < 1024; ++fd) close(fd);
        setenv("DEBIAN_FRONTEND", "noninteractive", 1);
        bool ok = run_libapt_transaction(action, targets, status_fd, false);
        cout.flush();
        cerr.flush();
        _exit(ok ? 0 : 1);
    }

    int host_status = 0;
    bool host_ok = false;
    if (host_pid > 0) {
        if (have_host_pipe) close(host_pipe[1]);

        std::atomic<int> host_percent(-1);
        ETAEstimator host_eta;

        std::thread host_reader([&]() {
            if (!have_host_pipe) return;
            FILE* f = fdopen(host_pipe[0], "r");
            if (!f) { close(host_pipe[0]); return; }
            char line[512];
            int last_shown = -1;
            while (fgets(line, sizeof(line), f) != NULL) {
                string s(line);
                bool is_pm = (s.size() > 9 && s.substr(0, 9) == "pmstatus:");
                bool is_dl = (!is_pm && s.size() > 9 && s.substr(0, 9) == "dlstatus:");
                if (!is_pm && !is_dl) continue;
                size_t c1 = s.find(':');
                if (c1 == string::npos) continue;
                size_t c2 = s.find(':', c1 + 1);
                if (c2 == string::npos) continue;
                size_t c3 = s.find(':', c2 + 1);
                if (c3 == string::npos) continue;
                string pct_str = s.substr(c2 + 1, c3 - c2 - 1);
                try {
                    int pct = static_cast<int>(stod(pct_str));
                    if (pct > host_percent.load()) host_percent.store(pct);
                    int current = host_percent.load();
                    if (current != last_shown) {
                        cout << TerminalProgressBar::render(current, "Applying to Host", host_eta.get_stats(current)) << flush;
                        last_shown = current;
                    }
                } catch (...) {}
            }
            fclose(f);
        });

        wait_for_child(host_pid, host_status);
        if (have_host_pipe) host_reader.join();
        host_ok = WIFEXITED(host_status) && WEXITSTATUS(host_status) == 0;
    }

    if (host_ok) {
        cout << TerminalProgressBar::render(100, "Transaction Applied Successfully", "Done") << "\n\n";
        create_snapshot("apt-post");
        cout << "\033[1;32m✔\033[0m Transaction completed successfully.\n";
    } else {
        cout << "\n\033[1;31mE:\033[0m Host transaction failed. Rolling back to previous snapshot...\n";
        global_config_backup.restore_orig();
        if (snapshot_created) do_rollback("apt-pre");
    }
}

void perform_transaction(const string& action, const vector<string>& pkgs, bool apply_host) {
    PrecheckResult precheck = precheck_transaction(action, pkgs, false);
    if (precheck == PrecheckResult::Failed || precheck == PrecheckResult::NoChanges) return;

    perform_transaction_argv(action, pkgs, apply_host);
}

void perform_install_transaction(const vector<string>& pkgs, bool apply_host, bool is_upgrade) {
    vector<InstallDecision> decisions;
    if (!resolve_install_decisions(pkgs, decisions, false, is_upgrade)) return;
    if (decisions.empty()) return;

    vector<string> args;
    for (const auto& decision : decisions) args.push_back(decision.apt_argument);

    perform_transaction_argv("install", args, apply_host);
}

void perform_global_upgrade(bool apply_host) {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return;

    vector<NaptRepoMetadata> repos = load_cached_napt_metadata();
    vector<string> napt_upgrade_args;

    auto get_installed_version = [&](const string& pkg_name) -> string {
        AptPackageState s = get_apt_package_state(cache_file, pkg_name);
        return s.installed ? s.installed_version : "";
    };

    auto try_queue_napt_upgrade = [&](const string& pkg_name, const string& installed_version) {
        NaptPackageCandidate candidate = find_best_napt_candidate(repos, pkg_name);
        if (!candidate.found) return;
        if (!installed_version.empty() && compare_versions(candidate.version, installed_version) <= 0) return;
        string local_path;
        if (!cache_napt_package(candidate, local_path)) return;
        if (candidate.sha256.empty()) {
            exec_argv_devnull_out({"rm", "-f", local_path});
            cout << "No SHA256 checksum found in metadata for " << pkg_name << ", skipping.\n";
            return;
        } else {
            string h = calculate_sha256(local_path);
            if (h != candidate.sha256) {
                exec_argv_devnull_out({"rm", "-f", local_path});
                cout << "Checksum mismatch for " << pkg_name << ", skipping.\n";
                return;
            }
        }
        cout << "Queuing napt upgrade: " << pkg_name;
        if (!installed_version.empty()) cout << " (" << installed_version << " -> " << candidate.version << ")";
        else cout << " (" << candidate.version << ")";
        cout << "\n";
        napt_upgrade_args.push_back(local_path);
    };

    set<string> handled_pkgs;
    for (const auto& repo : repos) {
        if (repo.required_packages.empty()) continue;
        string already_installed_req;
        for (const auto& req : repo.required_packages) {
            if (!get_installed_version(req).empty()) { already_installed_req = req; break; }
        }
        if (!already_installed_req.empty()) {
            string iv = get_installed_version(already_installed_req);
            try_queue_napt_upgrade(already_installed_req, iv);
            handled_pkgs.insert(already_installed_req);
        } else {
            for (const auto& req : repo.required_packages) {
                string iv = get_installed_version(req);
                NaptPackageCandidate c = find_best_napt_candidate(repos, req);
                if (!iv.empty()) {
                    if (c.found && compare_versions(c.version, iv) > 0) {
                        cout << "Upgrading required package: " << req << " (" << iv << " -> " << c.version << ")\n";
                        try_queue_napt_upgrade(req, iv);
                        handled_pkgs.insert(req);
                    }
                    continue;
                }
                if (c.found) {
                    cout << "Installing required package: " << req << "\n";
                    perform_install_transaction({req}, apply_host);
                    handled_pkgs.insert(req);
                } else {
                    AptPackageState apt_state = get_apt_package_state(cache_file, req);
                    if (apt_state.found) {
                        cout << "Installing required package: " << req << "\n";
                        perform_install_transaction({req}, apply_host);
                        handled_pkgs.insert(req);
                    } else {
                        cout << "Warning: required package " << req << " not found in any repo, skipping.\n";
                    }
                }
            }
        }
    }

    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        if (pkg->CurrentVer == 0) continue;
        string pkg_name = pkg.Name();
        if (handled_pkgs.count(pkg_name)) continue;
        AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
        try_queue_napt_upgrade(pkg_name, apt_state.installed_version);
    }

    if (!napt_upgrade_args.empty()) {
        cout << "Upgrading NAPT packages first...\n";
        perform_transaction_argv("install", napt_upgrade_args, apply_host);
    }

    cout << "Proceeding with standard apt upgrade...\n";
    perform_transaction("upgrade", vector<string>(), apply_host);
}

void perform_upgrade_transaction(const vector<string>& pkgs, bool apply_host) {
    if (pkgs.empty()) { perform_global_upgrade(apply_host); return; }
    perform_install_transaction(pkgs, apply_host, true);
}

static string to_lower_copy(const string& s) {
    string r = s;
    transform(r.begin(), r.end(), r.begin(),
              [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return r;
}

int run_search(const vector<string>& terms, int page) {
    if (terms.empty()) { cout << "Usage: napt search <term> [-p <page>]\n"; return 1; }
    if (page < 1) page = 1;
    string term = to_lower_copy(terms[0]);
    const int page_size = 30;
    const int offset = (page - 1) * page_size;

    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) { _error->DumpErrors(); return 1; }

    int matches = 0;
    int shown = 0;
    set<string> seen_names;

    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        string name = pkg.Name();
        if (to_lower_copy(name).find(term) == string::npos) continue;
        if (!seen_names.insert(name).second) continue;

        int index = matches;
        ++matches;
        if (index < offset || shown >= page_size) continue;

        pkgCache::VerIterator ver = pkg.VersionList();
        string version = ver.end() ? "" : ver.VerStr();

        cout << name;
        if (!version.empty()) cout << " (" << version << ")";
        cout << "\n";
        ++shown;
    }

    vector<NaptRepoMetadata> repos = load_cached_napt_metadata();
    for (const auto& repo : repos) {
        for (const auto& entry : repo.packages) {
            const string& pkg_name = entry.first;
            if (to_lower_copy(pkg_name).find(term) == string::npos) continue;

            int index = matches;
            ++matches;
            if (index < offset || shown >= page_size) continue;

            string version = extract_napt_version(pkg_name, entry.second.first);
            cout << pkg_name << " - Provided by Napt repository " << repo.base_url;
            if (!version.empty()) cout << ", version " << version;
            cout << ".\n";
            ++shown;
        }
    }

    if (matches == 0) {
        cout << "No packages found matching \"" << terms[0] << "\".\n";
        return 0;
    }

    if (shown == 0) {
        cout << "Page " << page << " is empty. This search has " << matches << " results.\n";
        return 0;
    }

    int total_pages = (matches + page_size - 1) / page_size;
    cout << "Page " << page << " of " << total_pages << " (" << matches << " total results).";
    if (page < total_pages) cout << " Use -p " << (page + 1) << " to see more.";
    cout << "\n";
    return 0;
}

int show_package_info(const string& pkg_name) {
    if (pkg_name.empty()) {
        cout << "Usage: napt info <package_name>\n";
        return 1;
    }

    pkgCacheFile cache_file;
    vector<NaptRepoMetadata> repos = load_cached_napt_metadata();
    AptPackageState apt_state = get_apt_package_state(cache_file, pkg_name);
    NaptPackageCandidate napt_cand = find_best_napt_candidate(repos, pkg_name);

    if (!apt_state.found && !napt_cand.found) {
        cout << "Package '" << pkg_name << "' not found in any configured repository.\n";
        return 1;
    }

    string cyan_bold = "\033[1;36m";
    string green = "\033[1;32m";
    string yellow = "\033[1;33m";
    string reset = "\033[0m";

    cout << cyan_bold << "Package Information: " << pkg_name << reset << "\n";
    cout << "----------------------------------------\n";
    cout << "Installed:     " << (apt_state.installed ? (green + "yes (" + apt_state.installed_version + ")" + reset) : "no") << "\n";

    if (napt_cand.found) {
        cout << "Napt Source:   " << napt_cand.base_url << " (" << napt_cand.release << ")\n";
        cout << "Napt File:     " << napt_cand.file_name << "\n";
        cout << "Napt Version:  " << napt_cand.version << "\n";
        cout << "SHA256:        " << (napt_cand.sha256.empty() ? "None" : napt_cand.sha256) << "\n";
        if (napt_cand.is_replacement) {
            cout << "Replaces Rule: " << yellow << "Replaces package '" << napt_cand.original_query_name 
                 << "' with '" << napt_cand.actual_pkg_name << "'" << reset << "\n";
        }
    }

    if (apt_state.found && !apt_state.candidate_version.empty()) {
        cout << "Debian Ver:    " << apt_state.candidate_version << "\n";
    }

    return 0;
}

int list_installed_packages() {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return 1;

    int count = 0;
    for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
        if (pkg->CurrentVer != 0) {
            cout << pkg.Name() << " (" << pkg.CurrentVer().VerStr() << ")\n";
            count++;
        }
    }
    cout << "\nTotal installed packages: " << count << "\n";
    return 0;
}

bool check_system_locks(bool quiet = false) {
    int fd = open("/var/lib/dpkg/lock-frontend", O_RDWR | O_CREAT | O_CLOEXEC, 0640);
    if (fd >= 0) {
        struct flock fl;
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(fd, F_SETLK, &fl) == -1) {
            close(fd);
            if (!quiet) {
                cout << "\033[1;31mE:\033[0m dpkg lock (/var/lib/dpkg/lock-frontend) is currently held by another process.\n";
                cout << "Please wait for the background package operation to complete.\n";
            }
            return false;
        }
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
    }
    return true;
}

int show_package_why(const string& pkg_name) {
    if (pkg_name.empty()) {
        cout << "Usage: napt why <package_name>\n";
        return 1;
    }
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return 1;

    pkgCache::PkgIterator target_pkg = cache->FindPkg(pkg_name);
    if (target_pkg.end()) {
        cout << "Package '" << pkg_name << "' not found.\n";
        return 1;
    }

    if (target_pkg->CurrentVer == 0) {
        cout << "Package '" << pkg_name << "' is not currently installed.\n";
    }

    string cyan_bold = "\033[1;36m";
    string green = "\033[1;32m";
    string gray = "\033[38;2;148;163;184m";
    string reset = "\033[0m";

    cout << cyan_bold << "Dependency Tree (Why is '" << pkg_name << "' required?):" << reset << "\n";
    cout << "--------------------------------------------------------\n";

    int rev_count = 0;
    set<string> seen_parents;

    for (pkgCache::DepIterator dep = target_pkg.RevDependsList(); !dep.end(); ++dep) {
        if (dep->Type != pkgCache::Dep::Depends && dep->Type != pkgCache::Dep::PreDepends) continue;
        pkgCache::PkgIterator parent = dep.ParentPkg();
        if (parent->CurrentVer != 0) {
            string pname = parent.Name();
            if (seen_parents.insert(pname).second) {
                cout << "  " << green << "✔ " << pname << reset << " (" << parent.CurrentVer().VerStr() << ")"
                     << gray << " [requires " << dep.DepType() << ": " << pkg_name << "]" << reset << "\n";
                rev_count++;
            }
        }
    }

    if (rev_count == 0) {
        cout << "  " << gray << "No installed packages depend on '" << pkg_name << "'. It was likely installed manually or as a top-level requirement." << reset << "\n";
    } else {
        cout << "\nRequired by " << rev_count << " currently installed package(s).\n";
    }
    return 0;
}

int show_package_depends(const string& pkg_name) {
    if (pkg_name.empty()) {
        cout << "Usage: napt depends <package_name>\n";
        return 1;
    }
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    if (cache == nullptr) return 1;

    pkgCache::PkgIterator target_pkg = cache->FindPkg(pkg_name);
    if (target_pkg.end()) {
        cout << "Package '" << pkg_name << "' not found.\n";
        return 1;
    }

    pkgCache::VerIterator ver = target_pkg.CurrentVer() != 0 ? target_pkg.CurrentVer() : target_pkg.VersionList();
    if (ver.end()) {
        cout << "No versions available for package '" << pkg_name << "'.\n";
        return 1;
    }

    string cyan_bold = "\033[1;36m";
    string green = "\033[1;32m";
    string yellow = "\033[1;33m";
    string reset = "\033[0m";

    cout << cyan_bold << "Direct Dependencies for '" << pkg_name << "' (" << ver.VerStr() << "):" << reset << "\n";
    cout << "--------------------------------------------------------\n";

    for (pkgCache::DepIterator dep = ver.DependsList(); !dep.end(); ++dep) {
        string type_name = dep.DepType();
        string target_name = dep.TargetPkg().Name();
        string color = (type_name == "Depends" || type_name == "PreDepends") ? green : yellow;
        cout << "  " << color << type_name << ": " << reset << target_name;
        if (dep.TargetVer() != nullptr) cout << " (" << dep.CompType() << " " << dep.TargetVer() << ")";
        cout << "\n";
    }
    return 0;
}

int show_history() {
    cout << "\033[1;36m=== NAPT Transaction History ===\033[0m\n\n";
    string log_path = "/var/log/dpkg.log";
    if (!fs::exists(log_path)) {
        cout << "No package history log found at " << log_path << ".\n";
        return 0;
    }

    ifstream in(log_path);
    if (!in.is_open()) {
        cout << "Unable to open history log.\n";
        return 1;
    }

    string line;
    vector<string> relevant_lines;
    while (getline(in, line)) {
        if (line.find(" install ") != string::npos ||
            line.find(" upgrade ") != string::npos ||
            line.find(" remove ") != string::npos ||
            line.find(" purge ") != string::npos) {
            relevant_lines.push_back(line);
        }
    }

    size_t start = (relevant_lines.size() > 25) ? (relevant_lines.size() - 25) : 0;
    for (size_t i = start; i < relevant_lines.size(); ++i) {
        const string& l = relevant_lines[i];
        if (l.find(" install ") != string::npos) {
            cout << "\033[1;32m[INSTALL]\033[0m " << l << "\n";
        } else if (l.find(" upgrade ") != string::npos) {
            cout << "\033[1;33m[UPGRADE]\033[0m " << l << "\n";
        } else if (l.find(" remove ") != string::npos || l.find(" purge ") != string::npos) {
            cout << "\033[1;31m[REMOVE]\033[0m  " << l << "\n";
        }
    }
    return 0;
}

int show_stats() {
    pkgCacheFile cache_file;
    pkgCache* cache = cache_file.GetPkgCache();
    vector<NaptRepoMetadata> repos = load_cached_napt_metadata();
    vector<NaptSource> sources = load_napt_sources();

    int total_pkgs = 0;
    int installed_pkgs = 0;

    if (cache != nullptr) {
        for (pkgCache::PkgIterator pkg = cache->PkgBegin(); !pkg.end(); ++pkg) {
            total_pkgs++;
            if (pkg->CurrentVer != 0) installed_pkgs++;
        }
    }

    uint64_t cache_bytes = 0;
    error_code ec;
    if (fs::exists(NAPT_CACHE_DIR, ec)) {
        for (const auto& entry : fs::recursive_directory_iterator(NAPT_CACHE_DIR, ec)) {
            if (entry.is_regular_file()) cache_bytes += entry.file_size(ec);
        }
    }

    string cyan_bold = "\033[1;36m";
    string green = "\033[1;32m";
    string reset = "\033[0m";

    cout << cyan_bold << "=== Arvor NAPT System & Cache Statistics ===" << reset << "\n\n";
    cout << "  Napt Repositories Configured: " << green << sources.size() << reset << "\n";
    cout << "  Napt Metadata Sources Loaded: " << green << repos.size() << reset << "\n";
    cout << "  Total Package Symbols:        " << total_pkgs << "\n";
    cout << "  Installed Packages:           " << green << installed_pkgs << reset << "\n";
    cout << "  Napt Cache Disk Footprint:    " << format_bytes(cache_bytes) << " (" << NAPT_CACHE_DIR << ")\n";
    cout << "  LVM Snapshot Sandbox Engine:  " << green << "Active (Thin / Thick LVM Supported)" << reset << "\n\n";
    return 0;
}

void do_transaction_rollback() {
    cout << "\033[1;33m==>\033[0m Querying available recovery snapshots for rollback...\n";
    string latest_snap = get_latest_snapshot("apt-pre");
    if (latest_snap.empty()) {
        latest_snap = get_latest_snapshot("root-auto");
    }

    if (latest_snap.empty()) {
        cout << "\033[1;31mE:\033[0m No automatic pre-transaction snapshots found in " << AUTO_SNAP_DIR << ".\n";
        cout << "Hint: You can use 'arvorctl rollback b' to restore to the last boot snapshot.\n";
        return;
    }

    cout << "Found latest pre-transaction snapshot: \033[1;32m" << latest_snap << "\033[0m\n";
    cout << "Are you sure you want to rollback to this snapshot? Type 'yes' to proceed: ";
    string confirm;
    getline(cin, confirm);
    if (confirm == "yes" || confirm == "YES") {
        do_rollback("apt-pre");
    } else {
        cout << "Rollback cancelled.\n";
    }
}

int main(int argc, char** argv) {
    setup_safety_handlers();
    pkgInitConfig(*_config);
    pkgInitSystem(*_config, _system);
    string command;
    vector<string> pkgs;
    bool apply_host = false;
    int search_page = 1;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-h" || arg == "--help") { show_help(); return 0; }
        else if (arg == "--v" || arg == "-v" || arg == "--version") { cout << "napt 4.1\n"; return 0; }
        else if (arg == "--vb") { _config->Set("Debug::pkgAcquire", "true"); }
        else if (arg == "--apply-host") { apply_host = true; }
        else if (arg == "--no-seccomp") { g_enable_seccomp = false; }
        else if (arg == "-y" || arg == "--yes" || arg == "--assume-yes") { assume_yes = true; }
        else if (arg == "-p" && i + 1 < argc) { search_page = atoi(argv[++i]); }
        else if (command.empty() && arg[0] != '-') { command = arg; }
        else if (arg[0] != '-') { pkgs.push_back(arg); }
    }

    if (command.empty()) { show_help(); return 0; }

    if (command == "moo") {
        if (!pkgs.empty() && pkgs[0] == "moo") {
            cout << "There are no easter eggs in this program.\n";
        } else {
            cout << "         (__) \n"
                 << "         (oo) \n"
                 << "   /------\\/ \n"
                 << "  / |    ||  \n"
                 << " *  ||---||  \n"
                 << "    ^^   ^^  \n"
                 << "...Have you mooed today?\n";
        }
        return 0;
    }

    if (command == "stats") {
        return show_stats();
    } else if (command == "history" || command == "log") {
        return show_history();
    } else if (command == "why") {
        if (pkgs.empty()) { cout << "Usage: napt why <package_name>\n"; return 1; }
        return show_package_why(pkgs[0]);
    } else if (command == "depends" || command == "deps") {
        if (pkgs.empty()) { cout << "Usage: napt depends <package_name>\n"; return 1; }
        return show_package_depends(pkgs[0]);
    } else if (command == "info" || command == "show") {
        if (pkgs.empty()) { cout << "Usage: napt info <package_name>\n"; return 1; }
        return show_package_info(pkgs[0]);
    } else if (command == "list" || command == "list-installed") {
        return list_installed_packages();
    } else if (command == "search") {
        return run_search(pkgs, search_page);
    }

    if (geteuid() != 0) { cout << "Root privileges required.\n"; return 1; }

    if (!check_system_locks()) return 1;

    if (command == "sync") {
        pkgCacheFile cache_file;
        pkgSourceList* src_list = cache_file.GetSourceList();
        bool apt_ok = false;
        if (src_list != nullptr) {
            NaptAcquireStatus status(-1, true, "metadata");
            apt_ok = ListUpdate(status, *src_list);
            if (!apt_ok) _error->DumpErrors();
        } else {
            _error->DumpErrors();
        }
        bool napt_ok = sync_napt_metadata();
        return (apt_ok && napt_ok) ? 0 : 1;
    } else if (command == "clean") {
        return clean_napt_cache() ? 0 : 1;
    } else if (command == "autoclean") {
        return autoclean_napt_cache() ? 0 : 1;
    } else if (command == "rollback") {
        do_transaction_rollback();
    } else if (command == "dist-upgrade") {
#ifdef nflinux
        do_nflinux_upgrade(apply_host);
#else
        perform_transaction("dist-upgrade", pkgs, apply_host);
#endif
    } else if (command == "install") {
        perform_install_transaction(pkgs, apply_host);
    } else if (command == "upgrade") {
        perform_upgrade_transaction(pkgs, apply_host);
    } else if (command == "remove" || command == "purge") {
        perform_transaction(command, pkgs, apply_host);
    } else {
        cout << "Unknown command: " << command << "\n";
        show_help();
        return 1;
    }

    return 0;
}
