/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @example ivfilterbench.cc
 *
 * Times kernel vs userspace system-call filtering. Attaches to a Windows guest,
 * counts SYSCALL/SYSRET events for a fixed duration, writes JSON, and can
 * compare two runs (module param off vs on).
 */

#include <introvirt/introvirt.hh>

#include <boost/program_options.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <time.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace introvirt;
using namespace introvirt::windows;

namespace po = boost::program_options;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

std::unique_ptr<Domain> domain;

void sig_handler(int) {
    if (domain)
        domain->interrupt();
}

class BenchCallback final : public EventCallback {
  public:
    explicit BenchCallback(bool hook_returns) : hook_returns_(hook_returns) {}

    void process_event(Event& event) override {
        switch (event.type()) {
        case EventType::EVENT_FAST_SYSCALL:
            if (hook_returns_)
                event.syscall().hook_return(true);
            syscalls_.fetch_add(1, std::memory_order_relaxed);
            break;
        case EventType::EVENT_FAST_SYSCALL_RET:
            sysrets_.fetch_add(1, std::memory_order_relaxed);
            break;
        default:
            break;
        }
    }

    uint64_t syscalls() const { return syscalls_.load(std::memory_order_relaxed); }
    uint64_t sysrets() const { return sysrets_.load(std::memory_order_relaxed); }

  private:
    bool hook_returns_;
    std::atomic<uint64_t> syscalls_{0};
    std::atomic<uint64_t> sysrets_{0};
};

struct BenchResult {
    std::string timestamp;
    std::string domain;
    double seconds_requested = 0;
    double seconds_elapsed = 0;
    std::string mode;
    bool deliver_returns = true;
    int module_param = 0;
    bool page_mapped = false;
    uint64_t userspace_syscalls = 0;
    uint64_t userspace_sysrets = 0;
    uint64_t kernel_syscalls_seen = 0;
    uint64_t kernel_syscalls_filtered = 0;
    uint64_t kernel_syscalls_delivered = 0;
    uint64_t kernel_sysrets_skipped = 0;
    uint64_t kernel_sysrets_delivered = 0;
    uint64_t event_block_ns = 0;
    uint64_t sysret_pending_overflow = 0;
};

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\')
            out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

static std::string now_iso8601() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

static std::string to_json(const BenchResult& r) {
    const double us_rate =
        r.seconds_elapsed > 0.0 ? static_cast<double>(r.userspace_syscalls) / r.seconds_elapsed : 0.0;
    const double ur_rate =
        r.seconds_elapsed > 0.0 ? static_cast<double>(r.userspace_sysrets) / r.seconds_elapsed : 0.0;

    std::ostringstream ss;
    ss << std::boolalpha << std::fixed;
    ss << "{\n";
    ss << "  \"timestamp\": \"" << json_escape(r.timestamp) << "\",\n";
    ss << "  \"domain\": \"" << json_escape(r.domain) << "\",\n";
    ss << "  \"seconds_requested\": " << r.seconds_requested << ",\n";
    ss << "  \"seconds_elapsed\": " << r.seconds_elapsed << ",\n";
    ss << "  \"mode\": \"" << json_escape(r.mode) << "\",\n";
    ss << "  \"deliver_returns\": " << r.deliver_returns << ",\n";
    ss << "  \"module_param\": " << r.module_param << ",\n";
    ss << "  \"page_mapped\": " << r.page_mapped << ",\n";
    ss << "  \"userspace_syscalls\": " << r.userspace_syscalls << ",\n";
    ss << "  \"userspace_sysrets\": " << r.userspace_sysrets << ",\n";
    ss << "  \"userspace_syscall_per_sec\": " << us_rate << ",\n";
    ss << "  \"userspace_sysret_per_sec\": " << ur_rate << ",\n";
    ss << "  \"kernel_syscalls_seen\": " << r.kernel_syscalls_seen << ",\n";
    ss << "  \"kernel_syscalls_filtered\": " << r.kernel_syscalls_filtered << ",\n";
    ss << "  \"kernel_syscalls_delivered\": " << r.kernel_syscalls_delivered << ",\n";
    ss << "  \"kernel_sysrets_skipped\": " << r.kernel_sysrets_skipped << ",\n";
    ss << "  \"kernel_sysrets_delivered\": " << r.kernel_sysrets_delivered << ",\n";
    ss << "  \"event_block_ns\": " << r.event_block_ns << ",\n";
    ss << "  \"sysret_pending_overflow\": " << r.sysret_pending_overflow << "\n";
    ss << "}\n";
    return ss.str();
}

static std::string json_raw_value(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos)
        throw std::runtime_error("JSON missing key: " + key);
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        ++pos;
    if (pos >= json.size())
        throw std::runtime_error("JSON truncated at key: " + key);

    if (json[pos] == '"') {
        ++pos;
        auto end = json.find('"', pos);
        if (end == std::string::npos)
            throw std::runtime_error("JSON unterminated string for key: " + key);
        return json.substr(pos, end - pos);
    }

    auto end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != '\n')
        ++end;
    std::string val = json.substr(pos, end - pos);
    while (!val.empty() && (val.back() == ' ' || val.back() == '\r'))
        val.pop_back();
    return val;
}

static BenchResult from_json(const std::string& path) {
    std::ifstream in(path);
    if (!in)
        throw std::runtime_error("Failed to read " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string json = ss.str();

    BenchResult r;
    r.timestamp = json_raw_value(json, "timestamp");
    r.domain = json_raw_value(json, "domain");
    r.seconds_requested = std::stod(json_raw_value(json, "seconds_requested"));
    r.seconds_elapsed = std::stod(json_raw_value(json, "seconds_elapsed"));
    r.mode = json_raw_value(json, "mode");
    r.deliver_returns = json_raw_value(json, "deliver_returns") == "true";
    r.module_param = std::stoi(json_raw_value(json, "module_param"));
    r.page_mapped = json_raw_value(json, "page_mapped") == "true";
    r.userspace_syscalls = std::stoull(json_raw_value(json, "userspace_syscalls"));
    r.userspace_sysrets = std::stoull(json_raw_value(json, "userspace_sysrets"));
    r.kernel_syscalls_seen = std::stoull(json_raw_value(json, "kernel_syscalls_seen"));
    r.kernel_syscalls_filtered = std::stoull(json_raw_value(json, "kernel_syscalls_filtered"));
    r.kernel_syscalls_delivered = std::stoull(json_raw_value(json, "kernel_syscalls_delivered"));
    r.kernel_sysrets_skipped = std::stoull(json_raw_value(json, "kernel_sysrets_skipped"));
    r.kernel_sysrets_delivered = std::stoull(json_raw_value(json, "kernel_sysrets_delivered"));
    r.event_block_ns = std::stoull(json_raw_value(json, "event_block_ns"));
    r.sysret_pending_overflow = std::stoull(json_raw_value(json, "sysret_pending_overflow"));
    return r;
}

static double rate(uint64_t count, double seconds) {
    return seconds > 0.0 ? static_cast<double>(count) / seconds : 0.0;
}

static double pct_change(double a, double b) {
    if (a == 0.0)
        return b == 0.0 ? 0.0 : 100.0;
    return ((b - a) / a) * 100.0;
}

static double block_ms_per_sec(uint64_t event_block_ns, double seconds) {
    return seconds > 0.0 ? (static_cast<double>(event_block_ns) / 1.0e6) / seconds : 0.0;
}

static double filter_pct(uint64_t seen, uint64_t filtered) {
    return seen == 0 ? 0.0 : (static_cast<double>(filtered) / static_cast<double>(seen)) * 100.0;
}

static void print_table(const BenchResult& r) {
    std::cout << '\n';
    std::cout << "=== ivfilterbench result ===\n";
    std::cout << "  domain                 : " << r.domain << '\n';
    std::cout << "  mode                   : " << r.mode << '\n';
    std::cout << "  deliver_returns        : " << (r.deliver_returns ? "true" : "false") << '\n';
    std::cout << "  page_mapped            : " << (r.page_mapped ? "true" : "false") << '\n';
    std::cout << "  module_param           : " << r.module_param << '\n';
    std::cout << "  elapsed                : " << std::fixed << std::setprecision(2)
              << r.seconds_elapsed << " s\n";
    std::cout << "  userspace SYSCALL      : " << r.userspace_syscalls << "  ("
              << std::setprecision(1) << rate(r.userspace_syscalls, r.seconds_elapsed)
              << "/s)\n";
    std::cout << "  userspace SYSRET       : " << r.userspace_sysrets << "  ("
              << rate(r.userspace_sysrets, r.seconds_elapsed) << "/s)\n";
    std::cout << "  kernel seen            : " << r.kernel_syscalls_seen << "  ("
              << std::setprecision(1) << rate(r.kernel_syscalls_seen, r.seconds_elapsed)
              << "/s)\n";
    std::cout << "  kernel filtered        : " << r.kernel_syscalls_filtered << "  ("
              << std::setprecision(2)
              << filter_pct(r.kernel_syscalls_seen, r.kernel_syscalls_filtered) << "% of seen)\n";
    std::cout << "  kernel delivered       : " << r.kernel_syscalls_delivered << '\n';
    std::cout << "  kernel sysret skipped  : " << r.kernel_sysrets_skipped << '\n';
    std::cout << "  kernel sysret delivered: " << r.kernel_sysrets_delivered << '\n';
    std::cout << "  vCPU block             : " << std::setprecision(1)
              << (static_cast<double>(r.event_block_ns) / 1.0e6) << " ms  ("
              << block_ms_per_sec(r.event_block_ns, r.seconds_elapsed) << " ms/s)\n";
    if (r.sysret_pending_overflow)
        std::cout << "  sysret pending overflow: " << r.sysret_pending_overflow << '\n';
}

static void print_delta(const char* label, double a, double b, bool as_int = false) {
    const double d = pct_change(a, b);
    std::cout << "  " << std::left << std::setw(32) << label << std::right;
    if (as_int)
        std::cout << static_cast<uint64_t>(a + 0.5) << "  ->  " << static_cast<uint64_t>(b + 0.5);
    else
        std::cout << std::fixed << std::setprecision(1) << a << "  ->  " << b;
    std::cout << "  (" << std::showpos << std::setprecision(1) << d << std::noshowpos << "%)\n";
}

static int compare_results(const std::string& path_a, const std::string& path_b) {
    const BenchResult a = from_json(path_a);
    const BenchResult b = from_json(path_b);

    std::cout << "A/B syscall filter comparison\n";
    std::cout << "  A: " << path_a << "  (module_param=" << a.module_param << ", " << a.mode << ", "
              << std::fixed << std::setprecision(1) << a.seconds_elapsed << "s)\n";
    std::cout << "  B: " << path_b << "  (module_param=" << b.module_param << ", " << b.mode << ", "
              << b.seconds_elapsed << "s)\n\n";

    if (a.mode != b.mode || a.deliver_returns != b.deliver_returns) {
        std::cerr << "WARNING: mode/deliver_returns differ; compare may not be apples-to-apples\n";
    }
    if (!a.page_mapped || !b.page_mapped) {
        std::cerr << "WARNING: page_mapped is false on one or both runs\n";
    }
    if (a.sysret_pending_overflow || b.sysret_pending_overflow) {
        std::cerr << "WARNING: sysret_pending_overflow is non-zero (A="
                  << a.sysret_pending_overflow << " B=" << b.sysret_pending_overflow << ")\n";
    }

    std::cout << "Guest impact:\n";
    print_delta("vCPU block ms/s", block_ms_per_sec(a.event_block_ns, a.seconds_elapsed),
                block_ms_per_sec(b.event_block_ns, b.seconds_elapsed));
    print_delta("Kernel seen/sec", rate(a.kernel_syscalls_seen, a.seconds_elapsed),
                rate(b.kernel_syscalls_seen, b.seconds_elapsed));

    std::cout << "\nFilter / delivery:\n";
    print_delta("Userspace SYSCALL/sec", rate(a.userspace_syscalls, a.seconds_elapsed),
                rate(b.userspace_syscalls, b.seconds_elapsed));
    print_delta("Userspace SYSRET/sec", rate(a.userspace_sysrets, a.seconds_elapsed),
                rate(b.userspace_sysrets, b.seconds_elapsed));
    print_delta("Kernel SYSCALL delivered", static_cast<double>(a.kernel_syscalls_delivered),
                static_cast<double>(b.kernel_syscalls_delivered), true);
    print_delta("Kernel SYSRET delivered", static_cast<double>(a.kernel_sysrets_delivered),
                static_cast<double>(b.kernel_sysrets_delivered), true);
    print_delta("Kernel filtered/seen %",
                filter_pct(a.kernel_syscalls_seen, a.kernel_syscalls_filtered),
                filter_pct(b.kernel_syscalls_seen, b.kernel_syscalls_filtered));

    std::cout << "\nInterpretation: with --narrow, kernel SYSRET delivered should fall to roughly\n"
                 "SYSCALL delivered (not kernel seen). vCPU block ms/s should drop; kernel seen/sec\n"
                 "should rise if pause time was the bottleneck. --wide should stay near 0% change.\n"
                 "userspace SYSRET/sec should track SYSCALL/sec when returns are hooked.\n";
    return 0;
}

static int measure(const po::variables_map& vm) {
    const std::string domain_name = vm["domain"].as<std::string>();
    const int seconds = vm["seconds"].as<int>();
    const bool wide = vm.count("wide") > 0;
    const bool no_returns = vm.count("no-returns") > 0;
    const std::string out_path = vm.count("output") ? vm["output"].as<std::string>() : "";

    if (seconds <= 0) {
        std::cerr << "ERROR: --seconds must be positive\n";
        return 1;
    }

    auto hypervisor = Hypervisor::instance();
    signal(SIGINT, &sig_handler);
    domain = hypervisor->attach_domain(domain_name);

    if (!domain->detect_guest()) {
        std::cerr << "Failed to detect guest OS\n";
        return 1;
    }
    if (domain->guest()->os() != OS::Windows) {
        std::cerr << "ivfilterbench only supports Windows guests\n";
        return 1;
    }

    auto* guest = static_cast<WindowsGuest*>(domain->guest());
    auto& filter = domain->system_call_filter();

    const bool mapped = filter.hypervisor_mapped();
    std::cout << "Kernel syscall filter page: " << (mapped ? "MAPPED" : "NOT MAPPED") << '\n';
    if (!mapped) {
        std::cerr << "ERROR: kernel filter page was not mapped. Wrong kvm-introvirt / libintrovirt "
                     "version?\n";
        return 1;
    }

    filter.enabled(true);
    filter.deliver_returns(!no_returns);

    if (wide) {
        guest->default_syscall_filter(filter);
        std::cout << "Filter mode: wide (default supported syscalls)\n";
    } else {
        guest->set_system_call_filter(filter, SystemCallIndex::NtCreateFile, true);
        guest->set_system_call_filter(filter, SystemCallIndex::NtOpenFile, true);
        guest->set_system_call_filter(filter, SystemCallIndex::NtClose, true);
        std::cout << "Filter mode: narrow (NtCreateFile, NtOpenFile, NtClose)\n";
    }
    std::cout << "deliver_returns: " << (filter.deliver_returns() ? "true" : "false") << '\n';
    std::cout << "hook_return: " << (no_returns ? "false" : "true") << '\n';

    domain->reset_syscall_filter_stats();
    const auto start_stats = domain->syscall_filter_stats();
    std::cout << "Module param introvirt_syscall_filter: "
              << (start_stats.kernel_filter_enabled ? 1 : 0) << '\n';

    domain->intercept_system_calls(true);

    BenchCallback callback(!no_returns);
    std::atomic<bool> stop_timer{false};
    std::thread timer([&]() {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        while (!stop_timer.load(std::memory_order_relaxed)) {
            if (std::chrono::steady_clock::now() >= deadline) {
                if (domain)
                    domain->interrupt();
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    const auto t0 = std::chrono::steady_clock::now();
    try {
        domain->poll(callback);
    } catch (...) {
        stop_timer.store(true, std::memory_order_relaxed);
        timer.join();
        throw;
    }
    stop_timer.store(true, std::memory_order_relaxed);
    const auto t1 = std::chrono::steady_clock::now();
    timer.join();

    const auto end_stats = domain->syscall_filter_stats();
    const double elapsed = std::chrono::duration<double>(t1 - t0).count();

    BenchResult result;
    result.timestamp = now_iso8601();
    result.domain = domain_name;
    result.seconds_requested = seconds;
    result.seconds_elapsed = elapsed;
    result.mode = wide ? "wide" : "narrow";
    result.deliver_returns = filter.deliver_returns();
    result.module_param = end_stats.kernel_filter_enabled ? 1 : 0;
    result.page_mapped = end_stats.page_mapped && mapped;
    result.userspace_syscalls = callback.syscalls();
    result.userspace_sysrets = callback.sysrets();
    result.kernel_syscalls_seen = end_stats.syscalls_seen;
    result.kernel_syscalls_filtered = end_stats.syscalls_filtered;
    result.kernel_syscalls_delivered = end_stats.syscalls_delivered;
    result.kernel_sysrets_skipped = end_stats.sysrets_skipped;
    result.kernel_sysrets_delivered = end_stats.sysrets_delivered;
    result.event_block_ns = end_stats.event_block_ns;
    result.sysret_pending_overflow = end_stats.sysret_pending_overflow;

    print_table(result);

    const std::string json = to_json(result);
    if (!out_path.empty()) {
        std::ofstream out(out_path);
        if (!out) {
            std::cerr << "ERROR: failed to write " << out_path << '\n';
            return 1;
        }
        out << json;
        std::cout << "Wrote " << out_path << '\n';
    } else {
        std::cout << '\n' << json;
    }

    return 0;
}

int main(int argc, char** argv) {
    po::options_description desc("Options");

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(), "The domain name or ID to attach to")
      ("seconds,s", po::value<int>()->default_value(30), "How long to sample")
      ("narrow", "Watch NtCreateFile/NtOpenFile/NtClose (default)")
      ("wide", "Watch the default supported syscall set")
      ("no-returns", "Ask KVM to drop SYSRET/SYSEXIT events (ceiling; no hook_return)")
      ("output,o", po::value<std::string>(), "Write JSON results to this file")
      ("compare", po::value<std::vector<std::string>>()->multitoken(),
       "Compare two JSON result files (off.json on.json)")
      ("help", "Display program help");
    // clang-format on

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    try {
        if (vm.count("compare"))
            return compare_results(vm["compare"].as<std::vector<std::string>>().at(0),
                                   vm["compare"].as<std::vector<std::string>>().at(1));
        return measure(vm);
    } catch (const TraceableException& ex) {
        std::cerr << "ERROR: " << ex << '\n';
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << '\n';
        return 1;
    }
}

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm) {
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            std::cout << "ivfilterbench - Measure kernel system-call filter A/B\n";
            std::cout << desc << '\n';
            std::cout << "Measure:\n"
                         "  ivfilterbench -D <domain> --seconds 30 --narrow -o run.json\n"
                         "Compare:\n"
                         "  ivfilterbench --compare off.json on.json\n";
            exit(0);
        }
        po::notify(vm);

        if (vm.count("compare")) {
            if (vm["compare"].as<std::vector<std::string>>().size() != 2) {
                std::cerr << "ERROR: --compare requires exactly two files\n";
                exit(1);
            }
            return;
        }
        if (!vm.count("domain")) {
            std::cerr << "ERROR: --domain is required unless using --compare\n";
            std::cerr << desc << '\n';
            exit(1);
        }
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << desc << std::endl;
        exit(1);
    }
}
