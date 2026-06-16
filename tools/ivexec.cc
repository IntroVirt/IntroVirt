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
 * @example ivexec.cc
 *
 * Executes a command in the guest by injecting a process creation (e.g.
 * NtCreateUserProcess/CreateProcess). Demonstrates system-call injection
 * and waiting for completion via event handling.
 */

#include "shared/SystemCallMonitor.hh"

#include <introvirt/introvirt.hh>
#include <introvirt/linux/inject/syscall.hh>

// Win11-compatible launch via NtCreateUserProcess syscall injection
#include <introvirt/windows/kernel/nt/NtKernel.hh>
#include <introvirt/windows/kernel/nt/const/ObjectType.hh>
#include <introvirt/windows/kernel/nt/const/ProcessCreateFlags.hh>
#include <introvirt/windows/kernel/nt/const/ThreadCreateFlags.hh>
#include <introvirt/windows/kernel/nt/syscall/NtCreateUserProcess.hh>
#include <introvirt/windows/kernel/nt/syscall/types/PS_CREATE_INFO.hh>
#include <introvirt/windows/kernel/nt/types/RTL_USER_PROCESS_PARAMETERS.hh>
#include <introvirt/windows/kernel/nt/types/access_mask/PROCESS_ACCESS_MASK.hh>
#include <introvirt/windows/kernel/nt/types/access_mask/THREAD_ACCESS_MASK.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_DIRECTORY.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER_NAME_INFO.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_SYMBOLIC_LINK.hh>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

#include <cctype>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

using namespace introvirt;
using namespace introvirt::windows;
using namespace introvirt::windows::nt;
using namespace introvirt::windows::kernel32;
using namespace introvirt::windows::condrv;

namespace po = boost::program_options;

void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm);

std::atomic_flag interrupted = false;
std::unique_ptr<Domain> domain;

void wait_for_timeout(unsigned int timeout) {
    // Try to sleep until the tool feels ready
    while (timeout) {
        timeout = sleep(timeout);
    }

    // Time expired,
    if (interrupted.test_and_set() == false) {
        std::cerr << "Time expired, exiting...\n";
        domain->interrupt();
    }
}

void sig_handler(int signum) {
    if (interrupted.test_and_set() == false) {
        std::cerr << "Interrupted by signal, exiting...\n";
        domain->interrupt();
    }
}

class ExecFileTool final : public EventCallback {
  public:
    ExecFileTool(Domain& domain, const std::string& launcher, const std::string& target,
                 const std::string& args, const std::string& directory, bool no_window,
                 bool show_exit_code, bool show_console_out, bool admin, uint64_t session_id,
                 SystemCallMonitor* system_call_monitor, bool all)
        : domain_(domain), guest_(static_cast<WindowsGuest&>(*domain_.guest())),
          launcher_(launcher), target_(target), args_(args), directory_(directory),
          show_exit_code_(show_exit_code), show_console_out_(show_console_out), admin_(admin),
          no_window_(no_window), session_id_(session_id), system_call_monitor_(system_call_monitor),
          unsupported_(all) {}

    /*
     * Resolve a drive-letter-qualified Win32 path ("C:\\dir\\file.exe") to a
     * session-independent NT object-namespace path
     * ("\\Device\\HarddiskVolumeN\\dir\\file.exe").
     *
     * NtCreateUserProcess opens the PsAttributeImageName value in the context
     * of the hijacked victim thread. The "\\??\\" prefix is a per-process /
     * per-session DosDevices alias resolved via the current thread's
     * EPROCESS.DeviceMap; on Win11 22621 that map may not expose the drive
     * letter in the injected context, yielding STATUS_OBJECT_PATH_INVALID
     * (0xC0000039) at PsCreateFailExeName. "\\Device\\HarddiskVolumeN" is a
     * real, global object with no DeviceMap/session dependency, so it resolves
     * identically in any thread.
     *
     * Resolution mirrors NtKernelImpl::reparse_drive_letters(): walk
     * RootDirectoryObject() -> the "GLOBAL??" OBJECT_DIRECTORY -> the "X:"
     * OBJECT_SYMBOLIC_LINK -> LinkTarget(). Returns "" if it cannot resolve,
     * so the caller can fall back to the legacy "\\??\\" form (Win10 path /
     * non-drive-letter targets).
     */
    std::string resolve_nt_device_path(const std::string& win32_path) const {
        // Need at least "X:\\..."; first two chars must be a drive letter + ':'.
        if (win32_path.size() < 3 || win32_path[1] != ':')
            return "";

        std::string letter(1, static_cast<char>(std::toupper(
                                  static_cast<unsigned char>(win32_path[0]))));
        if (!(letter[0] >= 'A' && letter[0] <= 'Z'))
            return "";
        letter += ':';
        const std::string remainder = win32_path.substr(2); // "\\Windows\\System32\\..."

        // KPTI/VCPU-running race: this object-namespace walk reads guest kernel
        // structures. A single sample can land on a user-CR3 / VCPU-running
        // moment where root / GLOBAL?? resolve as null or the link target reads
        // empty (or a read throws), yielding "" -> the caller falls back to
        // "\??\", which is invalid in the injected Win11 context ->
        // STATUS_OBJECT_PATH_NOT_FOUND / PsCreateFailOnFileOpen. Retry across
        // fresh samples so a transient miss doesn't fail the launch; a genuinely
        // absent drive letter just costs the (bounded) retry budget then falls back.
        constexpr int kResolveTries = 30;
        for (int attempt = 0; attempt < kResolveTries; ++attempt) {
            try {
                auto& kernel = guest_.kernel();
                auto root = kernel.RootDirectoryObject();
                if (root) {
                    // Find the \GLOBAL?? directory (global DosDevices, session-independent).
                    std::shared_ptr<nt::OBJECT_DIRECTORY> global;
                    for (const auto& obj : root->objects()) {
                        const auto& hdr = obj->header();
                        if (hdr.type() == nt::ObjectType::Directory && hdr.has_name_info() &&
                            hdr.NameInfo().Name() == "GLOBAL??") {
                            global = nt::OBJECT_DIRECTORY::make_shared(kernel, obj->ptr());
                            break;
                        }
                    }
                    // Find the "X:" symbolic link and read its target device path.
                    if (global) {
                        for (const auto& obj : global->objects()) {
                            const auto& hdr = obj->header();
                            if (hdr.type() != nt::ObjectType::SymbolicLink || !hdr.has_name_info())
                                continue;
                            if (!boost::iequals(hdr.NameInfo().Name(), letter))
                                continue;

                            auto link = nt::OBJECT_SYMBOLIC_LINK::make_shared(kernel, obj->ptr());
                            std::string target = link->LinkTarget(); // e.g. "\\Device\\HarddiskVolume3"
                            if (!target.empty()) {
                                // Strip a trailing backslash before appending remainder.
                                if (target.back() == '\\')
                                    target.pop_back();
                                return target + remainder; // "\\Device\\HarddiskVolume3\\Windows\\...\\file.exe"
                            }
                        }
                    }
                }
            } catch (std::exception& ex) {
                // transient racy walk; resample on the next attempt
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }
        return "";
    }

    /**
     * @brief Perform the actual injection to launch a process in the guest
     */
    bool launch(WindowsEvent& wevent) {
        /*
         * Launch the target via direct NtCreateUserProcess syscall injection.
         *
         * The previous implementation redirected RIP to call CreateProcessW
         * (function-call injection). On Windows 11 22621 the redirected
         * CreateProcessW faults when executed and bugchecks the guest
         * (IRQL_NOT_LESS_OR_EQUAL). Syscall injection is stable on both Win10
         * and Win11, so we build the structures CreateProcessW would otherwise
         * construct (RTL_USER_PROCESS_PARAMETERS / PS_ATTRIBUTE_LIST /
         * PS_CREATE_INFO) ourselves and invoke NtCreateUserProcess directly.
         */
        auto& kernel = guest_.kernel();

        std::string cmdline = target_;
        if (!args_.empty())
            cmdline += ' ' + args_;

        // The NT path is what NtCreateUserProcess uses to open the image; it is
        // passed via the PsAttributeImageName process attribute and resolved in
        // the injected victim thread's object/DeviceMap context. Prefer a
        // session-independent \Device\HarddiskVolumeN path (Win11-safe, since
        // "\??\" is a per-session/per-process DosDevices alias that may not
        // expose the drive letter in the injected context -> 0xC0000039 at
        // PsCreateFailExeName). Fall back to the legacy \??\ DosDevices alias if
        // resolution fails (Win10 path / non-drive-letter targets).
        std::string nt_image_path = resolve_nt_device_path(target_);
        if (nt_image_path.empty())
            nt_image_path = "\\??\\" + target_;
        const std::string current_dir =
            directory_.empty() ? std::string("C:\\Windows\\System32\\") : directory_;
        const std::string desktop = "Winsta0\\Default";

        // UTF-16 path strings, each its own guest allocation. The parameter
        // block is NORMALIZED, so it references these by absolute pointer.
        const std::u16string wImage = Utf16String::convert(target_);
        const std::u16string wCmd = Utf16String::convert(cmdline);
        const std::u16string wCurDir = Utf16String::convert(current_dir);
        const std::u16string wDesktop = Utf16String::convert(desktop);
        const std::u16string wNtImage = Utf16String::convert(nt_image_path);

        // NT image path (referenced by the attribute list) is a separate allocation.
        auto sNtImage = inject::allocate(wNtImage);

        // Minimal empty environment: a single UTF-16 NUL pair (double-null).
        auto env = inject::allocate<uint8_t[]>(4);
        {
            auto e = env.ptr();
            for (int i = 0; i < 4; ++i)
                e[i] = 0;
        }

        // ----- Build RTL_USER_PROCESS_PARAMETERS (x64), strings appended inline -----
        // RtlCreateProcessParametersEx lays the path strings out immediately after
        // the fixed header within the same block; each UNICODE_STRING.Buffer points
        // within [block, block+Length]. We reproduce that exactly.
        //
        // HDR must cover the FULL fixed header so trailing members
        // (EnvironmentSize@0x3F0, EnvironmentVersion@0x3F8, PackageDependencyData@0x400,
        // ProcessGroupId@0x408, LoaderThreads@0x40C, RedirectionDllName/HeapPartitionName/
        // DefaultThreadpoolCpuSetMasks...) are present and zeroed. On Win11 22H2 x64
        // sizeof(RTL_USER_PROCESS_PARAMETERS) is 0x440; using 0x410 would let the inline
        // path strings overlap those defined members.
        constexpr size_t HDR = 0x440;
        auto bytes = [](const std::u16string& s) { return (s.length() + 1) * 2; };
        const size_t offImage = HDR;
        const size_t offCmd = offImage + bytes(wImage);
        const size_t offCurDir = offCmd + bytes(wCmd);
        const size_t offDesktop = offCurDir + bytes(wCurDir);
        const size_t TOTAL = offDesktop + bytes(wDesktop);

        auto rupp = inject::allocate<uint8_t[]>(TOTAL);
        const uint64_t G = rupp.address();

        std::vector<uint8_t> b(TOTAL, 0);
        auto put16 = [&](size_t o, uint16_t v) {
            b[o] = v & 0xff;
            b[o + 1] = (v >> 8) & 0xff;
        };
        auto put32 = [&](size_t o, uint32_t v) {
            for (int i = 0; i < 4; ++i)
                b[o + i] = (v >> (8 * i)) & 0xff;
        };
        auto put64 = [&](size_t o, uint64_t v) {
            for (int i = 0; i < 8; ++i)
                b[o + i] = (v >> (8 * i)) & 0xff;
        };
        auto putStr = [&](size_t o, const std::u16string& s) {
            for (size_t i = 0; i < s.size(); ++i) {
                b[o + i * 2] = s[i] & 0xff;
                b[o + i * 2 + 1] = (s[i] >> 8) & 0xff;
            }
        };
        // UNICODE_STRING { USHORT Length; USHORT MaximumLength; <pad>; PWSTR Buffer; }
        auto putUS = [&](size_t field, size_t stroff, const std::u16string& s) {
            put16(field, s.length() * 2);             // Length (bytes, no NUL)
            put16(field + 2, (s.length() + 1) * 2);   // MaximumLength (incl NUL)
            put64(field + 8, G + stroff);             // Buffer (absolute, within block)
        };

        putStr(offImage, wImage);
        putStr(offCmd, wCmd);
        putStr(offCurDir, wCurDir);
        putStr(offDesktop, wDesktop);

        put32(0x00, TOTAL);                  // MaximumLength
        put32(0x04, TOTAL);                  // Length
        put32(0x08, 0x1);                    // Flags = NORMALIZED
        putUS(0x38, offCurDir, wCurDir);     // CurrentDirectory.DosPath (Handle @0x48 = 0)
        putUS(0x60, offImage, wImage);       // ImagePathName
        putUS(0x70, offCmd, wCmd);           // CommandLine
        put64(0x80, env.address());          // Environment
        putUS(0xB0, offImage, wImage);       // WindowTitle (reuse inline image buffer)
        putUS(0xC0, offDesktop, wDesktop);   // DesktopInfo
        put64(0x3F0, 4);                     // EnvironmentSize

        {
            auto p = rupp.ptr();
            for (size_t i = 0; i < TOTAL; ++i)
                p[i] = b[i];
        }

        // ----- Build PS_ATTRIBUTE_LIST with one PsAttributeImageName entry -----
        // PS_ATTRIBUTE_LIST { SIZE_T TotalLength; PS_ATTRIBUTE Attributes[1]; }
        // PS_ATTRIBUTE { ULONG_PTR Attribute; SIZE_T Size; ULONG_PTR Value; PSIZE_T ReturnLength; }
        constexpr size_t AL_SIZE = 0x28;
        std::vector<uint8_t> al(AL_SIZE, 0);
        auto putAL = [&](size_t o, uint64_t v) {
            for (int i = 0; i < 8; ++i)
                al[o + i] = (v >> (8 * i)) & 0xff;
        };
        // Attribute@0x08 is intentionally written 0 here and set below via the typed
        // PS_ATTRIBUTE setters, so the encoding is exactly the canonical
        // PsAttributeImageName = num 5 | PS_ATTRIBUTE_INPUT (0x20005). Hand-writing it
        // previously produced 0x60005 (an extra 0x40000 "additive/unknown" bit) which
        // PspValidateAttributeList rejects during early create-context build (before the
        // image file is opened), yielding STATUS_INVALID_PARAMETER with
        // PS_CREATE_INFO.State left at PsCreateInitialState.
        putAL(0x00, AL_SIZE);                  // TotalLength
        putAL(0x08, 0);                        // Attribute (set via typed setters below)
        putAL(0x10, wNtImage.length() * 2);    // Size (bytes, no NUL)
        putAL(0x18, sNtImage.address());       // Value -> NT image path
        putAL(0x20, 0);                        // ReturnLength
        auto attrlist = inject::allocate<uint8_t[]>(AL_SIZE);
        {
            auto p = attrlist.ptr();
            for (size_t i = 0; i < AL_SIZE; ++i)
                p[i] = al[i];
        }

        // Encode the attribute number/flags via IntroVirt's typed PS_ATTRIBUTE setters
        // so the value is provably 0x20005 (PsAttributeImageName, input-only,
        // non-thread, non-additive) rather than a hand-packed constant.
        {
            auto pal_set = PS_ATTRIBUTE_LIST::make_unique(kernel, attrlist);
            auto& attr = (*pal_set)[0];
            attr.AttributeNumber(PsAttributeImageName); // num 5
            attr.AttributeInputOnly(true);              // PS_ATTRIBUTE_INPUT (0x20000)
            attr.AttributeThreads(false);               // not a thread attribute
        }

        // ----- PS_CREATE_INFO: Size = sizeof (0x58), State = PsCreateInitialState (0) -----
        constexpr size_t PSCI_SIZE = 0x58;
        auto psci_buf = inject::allocate<uint8_t[]>(PSCI_SIZE);
        {
            auto p = psci_buf.ptr();
            for (size_t i = 0; i < PSCI_SIZE; ++i)
                p[i] = 0;
            for (int i = 0; i < 8; ++i)
                p[i] = (PSCI_SIZE >> (8 * i)) & 0xff; // Size
        }

        auto procParams = RTL_USER_PROCESS_PARAMETERS::make_unique(kernel, rupp);
        auto createInfo = PS_CREATE_INFO::make_unique(kernel, psci_buf);

        uint64_t hProcess = 0, hThread = 0;
        const guest_ptr<void> nullAttr;

        NTSTATUS status = inject::system_call<nt::NtCreateUserProcess>(
            hProcess, hThread, PROCESS_ACCESS_MASK(0x1FFFFF), THREAD_ACCESS_MASK(0x1FFFFF), nullAttr,
            nullAttr, ProcessCreateFlags(0), ThreadCreateFlags(nt::CREATE_SUSPENDED), procParams.get(),
            *createInfo, attrlist);

        if (!status.NT_SUCCESS() || hProcess == 0) {
            std::cerr << "Failed to launch process: NtCreateUserProcess returned " << status
                      << " (0x" << std::hex << status.value() << std::dec << ")"
                      << " PS_CREATE_INFO.State=" << createInfo->State() << '\n';
            return false;
        }

        // Resolve the new process from its handle (handle lives in the launcher's table).
        auto handle_table = wevent.task().pcr().CurrentThread().Process().ObjectTable();
        auto new_process = handle_table ? handle_table->ProcessObject(hProcess) : nullptr;
        new_pid_ = new_process ? new_process->UniqueProcessId() : 0;

        std::cerr << "Created process [" << new_pid_ << "]\n";

        // Reconfigure the task filter for our new PID
        domain_.task_filter().clear();
        domain_.task_filter().add_pid(new_pid_);

        if (admin_ && new_process) {
            auto& token = new_process->Token();
            token.PrivilegesPresent(0xFFFFFFFFFFFFFFFF);
            token.PrivilegesEnabled(0xFFFFFFFFFFFFFFFF);

            for (auto& group : token.Groups()) {
                if (group->Attributes().SE_GROUP_USE_FOR_DENY_ONLY()) {
                    SID_AND_ATTRIBUTES::SidAttributeFlags new_flags(
                        SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED);
                    group->Attributes(new_flags);
                }
            }
        }

        // Close the process handle, resume the suspended thread, close the thread handle.
        inject::system_call<nt::NtClose>(hProcess);
        inject::system_call<nt::NtResumeThread>(hThread, nullptr);
        inject::system_call<nt::NtClose>(hThread);

        return true;
    }

    bool matches_session_id(WindowsEvent& event) const {
        auto& process = event.task().pcr().CurrentThread().Process();
        return (process.Session() && process.Session()->SessionID() == session_id_);
    }

    bool has_user32(WindowsEvent& event) const {
        auto& process = event.task().pcr().CurrentThread().Process();
        auto vad = process.VadRoot();
        if (!vad)
            return false;

        for (auto& entry : vad->VadTreeInOrder()) {
            if (entry->FileObject()) {
                try {
                    std::string file_name(boost::to_lower_copy(entry->FileObject()->FileName()));
                    if (boost::ends_with(file_name, "user32.dll")) {
                        return true;
                    }
                } catch (VirtualAddressNotPresentException& ex) {
                }
            }
        }
        return false;
    }

    bool matches_launcher(WindowsEvent& event) const {
        return (launcher_.empty() || boost::starts_with(event.task().process_name(), launcher_));
    }

    void process_event(Event& event) override {
        if (unlikely(event.type() == EventType::EVENT_SHUTDOWN ||
                     event.type() == EventType::EVENT_REBOOT)) {
            exit(64);
        }

        WindowsEvent& wevent = static_cast<WindowsEvent&>(event);

        if (event.task().pid() != new_pid_) {
            if (wevent.task().pcr().CurrentThread().Teb() != nullptr) {
                if (posted_message_.test_and_set() == 0) {
#if 0 // Still seems unstable, disabling for now

                    if (!matches_launcher(wevent) && matches_session_id(wevent) &&
                        has_user32(wevent)) {
                        if (!inject::system_call<win32k::NtUserPostMessage>(
                                0xffff, win32k::WM_PAINT, 0, 0)) {
                            // Our message failed to post, try again
                            posted_message_.clear();
                        }
                    } else {
                        posted_message_.clear();
                    }
#endif
                    return;
                }
            }

            if (!matches_launcher(wevent) || !matches_session_id(wevent))
                return;

            if (started_.test_and_set() == 0) {
                posted_message_.test_and_set();

                // Perform injection to lauch the target process
                // The atomic_flag used above is so that we don't accidentally
                // do this simultaneously in multiple threads.

                if (!launch(wevent)) {
                    // Launch failed
                    domain_.interrupt();
                    return;
                }

                {
                    // This madness is in case the process terminates
                    // before our injection thread finishes
                    std::lock_guard lifelock(lifecycle_mtx_);
                    launched_ = true;
                    if (terminated_) {
                        domain_.interrupt();
                    }
                }

                // If we don't want to keep watching, we can exit now
                if (!system_call_monitor_ && !show_exit_code_ && !show_console_out_) {
                    domain_.interrupt();
                    return;
                }

                // Enable the system call filter now that we're launched
                if (!unsupported_)
                    domain_.system_call_filter().enabled(true);
            }
            return;
        }

        /*
         * If we're here, we're receiving an event from the target process!
         */
        if (event.type() == EventType::EVENT_FAST_SYSCALL) {
            switch (wevent.syscall().index()) {

            case SystemCallIndex::NtTerminateProcess: {
                auto* terminate_process =
                    static_cast<NtTerminateProcess*>(wevent.syscall().handler());

                if (!terminate_process->will_return()) {
                    if (show_exit_code_) {
                        std::cout << "Process Exited: " << terminate_process->ExitStatus() << " ("
                                  << terminate_process->ExitStatus().value() << ")\n";
                    }
                    std::lock_guard lifelock(lifecycle_mtx_);
                    terminated_ = true;
                    if (launched_)
                        domain_.interrupt();
                }

                break;
            }

            case SystemCallIndex::NtDeviceIoControlFile: {
                if (!show_console_out_)
                    break;

                auto* device_ioctl =
                    static_cast<NtDeviceIoControlFile*>(wevent.syscall().handler());

                // TODO: This is a duplicate check because ConDrvIoctl throws an exception if this
                // is not true. We need to handle more ioctl codes in ConDrvIoctl.
                if (device_ioctl->IoControlCode() !=
                    static_cast<uint32_t>(condrv::ConsoleRequestIoctl::ConsoleCallServerGeneric))
                    break;

                // Check the driver's filename instead of only relying on the ioctl number
                // auto* ObjectTable = wevent.task().pcr().CurrentThread().Process().ObjectTable();
                // if (!ObjectTable)
                //     break;

                // const auto* file = ObjectTable->FileObject(device_ioctl->FileHandle());
                // if (!file)
                //     break;

                // const auto* device = file->DeviceObject();
                // if (!device || device->DeviceName() != "ConDrv")
                //     break;

                // Check if it's a console ioctl code
                if (static_cast<ConsoleRequestIoctl>(device_ioctl->IoControlCode()) ==
                    ConsoleRequestIoctl::ConsoleCallServerGeneric) {

                    // Looks like a console ioctl, parse it
                    ConDrvIoctl console_ioctl(wevent.guest(), *device_ioctl);

                    // Check if the request is to write to the console
                    auto& requestData = console_ioctl.GenericRequest();
                    if (requestData.RequestCode() !=
                        ConsoleCallServerGenericRequestCode::WriteConsole)
                        break; // Nope

                    // Console write ioctl. Get the data and print it.
                    ConsoleCallServerGenericWriteRequest writeRequest(wevent.guest(), requestData);
                    std::cout << writeRequest.Data();
                }
                break;
            }
            default:
                // Some other call we don't care about
                break;
            }
        }

        if (system_call_monitor_) {
            // We have a system call monitor attached, so just give it events from now on
            system_call_monitor_->process_event(event);
            return;
        }
    }

    int result() { return result_; }

  private:
    Domain& domain_;
    WindowsGuest& guest_;

    std::string launcher_;
    std::string target_;
    std::string args_;
    std::string directory_;

    const bool show_exit_code_;
    const bool show_console_out_;
    const bool admin_;
    const bool no_window_;
    int result_ = 0;

    uint64_t new_pid_ = 0;
    uint64_t session_id_;

    std::atomic_flag started_ = false;
    std::atomic_flag posted_message_ = false;

    std::mutex lifecycle_mtx_;
    bool launched_ = false;
    bool terminated_ = false;

    SystemCallMonitor* system_call_monitor_;
    const bool unsupported_;
};

/*
 * Native-Linux process launch via fork()+execve() injection.
 *
 * execve replaces the current process image, so injecting it directly would
 * kill the host process. Instead we fork() a child from a victim process, then
 * execve() the target *in the child* (the victim survives). Two phases keyed on
 * the child's pid:
 *   1. On the first syscall event, inject fork() in the victim → child pid.
 *   2. The fork's child shares the victim's comm, so its syscall events are
 *      delivered too; on the first event with task().pid() == child, inject
 *      execve(target, argv, envp). The child becomes the sample.
 */
class LinuxExecTool final : public EventCallback {
  public:
    LinuxExecTool(std::string path, std::vector<std::string> argv, std::vector<std::string> envp)
        : path_(std::move(path)), argv_(std::move(argv)), envp_(std::move(envp)) {}

    int result() const { return result_; }

    void process_event(Event& event) override {
        if (unlikely(event.type() == EventType::EVENT_SHUTDOWN ||
                     event.type() == EventType::EVENT_REBOOT)) {
            exit(64);
        }
        if (event.type() != EventType::EVENT_FAST_SYSCALL)
            return;

        if (phase_ == Phase::Fork) {
            const int64_t child = linux_guest::inject::inject_fork(event);
            if (child <= 0) {
                std::cerr << "fork injection failed: " << child << '\n';
                event.domain().interrupt();
                return;
            }
            child_pid_ = static_cast<uint64_t>(child);
            std::cout << "Forked child pid " << child_pid_ << "; awaiting its first syscall\n";
            phase_ = Phase::Exec;
            return;
        }

        if (phase_ == Phase::Exec) {
            if (event.task().pid() != child_pid_)
                return; // not our child yet
            const int64_t r = linux_guest::inject::execve(event, path_, argv_, envp_);
            // execve only returns on failure.
            if (r < 0)
                std::cerr << "execve injection failed: " << r << '\n';
            else
                std::cout << "Launched " << path_ << " in pid " << child_pid_ << '\n';
            result_ = (r < 0) ? 1 : 0;
            phase_ = Phase::Done;
            event.domain().interrupt();
        }
    }

  private:
    enum class Phase { Fork, Exec, Done };
    Phase phase_ = Phase::Fork;
    const std::string path_;
    const std::vector<std::string> argv_;
    const std::vector<std::string> envp_;
    uint64_t child_pid_ = 0;
    int result_ = 1;
};

static int run_linux_exec(Domain& domain, const std::string& target,
                          const std::string& arguments, const std::string& process_name,
                          bool procname_set) {
    std::vector<std::string> argv{target};
    if (!arguments.empty()) {
        std::vector<std::string> parts;
        boost::split(parts, arguments, boost::is_any_of(" "), boost::token_compress_on);
        for (auto& p : parts)
            if (!p.empty())
                argv.push_back(p);
    }
    const std::vector<std::string> envp{
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"};

    // Host the fork in a named victim if given, else any process that syscalls.
    if (procname_set)
        domain.task_filter().add_name(process_name);

    domain.intercept_system_calls(true);
    LinuxExecTool tool(target, argv, envp);
    domain.poll(tool);
    return tool.result();
}

int main(int argc, char** argv) {
    po::options_description desc("Options");
    std::string domain_name;
    std::string process_name;
    std::string target_file;
    std::string arguments;
    std::string working_directory;
    unsigned int timeout;

    // clang-format off
    desc.add_options()
      ("domain,D", po::value<std::string>(&domain_name)->required(), "The domain name or ID attach to")
      ("target,t", po::value<std::string>(&target_file)->required(), "The target file to execute in the guest")
      ("args,a", po::value<std::string>(&arguments), "Arguments to pass to the executable")
      ("console,c", "Display console output from the launched process")
      ("directory,d", po::value<std::string>(&working_directory), "Set the working directory of the launched process")
      ("exitcode,e", "Wait for the program to exit and display the exit code")
      ("nowindow,n", "Do not create a window for the new process")
      ("admin", "Run as a privileged process. Removes default value for --procname.")
      ("timeout,T", po::value<unsigned int>(&timeout)->default_value(0), "A timeout after which we exit. 0 for infinite.")
      ("procname,P", po::value<std::string>(&process_name)->default_value("explorer"), "The name of a process to hijack")
      ("syscall,S", "Monitor system calls executed by the new process")
      ("no-flush", "Don't flush the output buffer after each event")
      ("json", "Output JSON format")
      ("help", "Display program help")
      ("unsupported", "Display system calls that we don't have handlers for (for syscalls)");
    // clang-format on

    for (auto& category : WindowsGuest::syscall_categories()) {
        desc.add_options()(category.c_str(),
                           std::string("Enable " + category + " related system calls").c_str());
    }

    // We're not mixing with printf, improve cout performance.
    std::cout.sync_with_stdio(false);

    po::variables_map vm;
    parse_program_options(argc, argv, desc, vm);

    // Get a hypervisor instance
    // This will automatically select the correct type of hypervisor.
    auto hypervisor = Hypervisor::instance();

    // Attach to the domain
    signal(SIGINT, &sig_handler);

    try {
        domain = hypervisor->attach_domain(domain_name);

        // Detect the guest OS
        if (!domain->detect_guest()) {
            std::cerr << "Failed to detect guest OS\n";
            return 1;
        }

        if (domain->guest()->os() == OS::Linux) {
            // Native-Linux launch via fork()+execve() injection (self-contained;
            // the Windows path below is untouched).
            return run_linux_exec(*domain, target_file, arguments, process_name,
                                  !vm["procname"].defaulted());
        }

        if (domain->guest()->os() != OS::Windows) {
            std::cerr << "Unsupported OS: " << domain->guest()->os() << '\n';
            return 1;
        }

        std::unique_ptr<SystemCallMonitor> syscall_monitor;
        if (vm.count("syscall")) {
            if (vm.count("exitcode") || vm.count("console")) {
                std::cerr << "Cannot use --syscall mode with --exitcode or --console\n";
                return 10;
            }
            syscall_monitor = std::make_unique<SystemCallMonitor>(
                !vm.count("no-flush"), vm.count("json"), vm.count("unsupported"));

            // Turn on system call filtering unless hooking all calls
            if (vm.count("unsupported") == 0) {
                bool category_used = false;

                if (domain->guest()->os() == OS::Windows) {
                    for (auto& category : WindowsGuest::syscall_categories()) {
                        if (vm.count(category)) {
                            auto* guest = static_cast<WindowsGuest*>(domain->guest());
                            guest->enable_category(category, domain->system_call_filter());
                            category_used = true;
                        }
                    }
                }

                if (!category_used) {
                    // Default to all supported calls
                    if (domain->guest()->os() == OS::Windows) {
                        auto* guest = static_cast<WindowsGuest*>(domain->guest());
                        guest->default_syscall_filter(domain->system_call_filter());
                    }
                }
            }
        }

        // Configure the system call filter, but don't activate it yet
        auto* guest = static_cast<WindowsGuest*>(domain->guest());
        guest->set_system_call_filter(domain->system_call_filter(),
                                      SystemCallIndex::NtTerminateProcess, true);

        // Get the session id for the target process.
        // KPTI/VCPU-running race: a single CidTable walk can land on a user-CR3 /
        // VCPU-running moment where the kernel reads (CidTable / open_handles /
        // ObjectHeader / process->Session()) transiently fail. The original
        // single-shot walk then reported "Failed to find the session ID"; worse,
        // CidTable()/open_handles() sat OUTSIDE the per-entry try, so a raced read
        // there threw a CommandFailedException ("Cannot access register state
        // while VCPU is running") straight to std::terminate. Retry the whole walk
        // across fresh samples, catching the walk-level read as well.
        uint64_t session_id = 0xFFFFFFFFFFFFFFFF;
        auto& kernel = guest->kernel();
        constexpr int kSessionTries = 40;
        for (int attempt = 0;
             attempt < kSessionTries && session_id == 0xFFFFFFFFFFFFFFFF; ++attempt) {
            try {
                auto CidTable = kernel.CidTable();
                auto handles = CidTable->open_handles();
                for (auto& entry : handles) {
                    try {
                        if (entry->ObjectHeader()->type() == ObjectType::Process) {
                            auto process = kernel.process(entry->ObjectHeader()->Body());
                            if (boost::istarts_with(process->ImageFileName(), process_name)) {
                                // Found the target process
                                if (process->Session()) {
                                    session_id = process->Session()->SessionID();
                                    break;
                                }
                            }
                        }
                    } catch (TraceableException& ex) {
                        // racy per-entry read; skip this entry
                    }
                }
            } catch (TraceableException& ex) {
                // racy walk-level read (CidTable/open_handles unreadable at this
                // CR3); resample on the next attempt
            }
            if (session_id == 0xFFFFFFFFFFFFFFFF)
                std::this_thread::sleep_for(std::chrono::milliseconds(40));
        }

        if (session_id == 0xFFFFFFFFFFFFFFFF) {
            std::cerr << "Failed to find the session ID of the target process" << std::endl;
            return 20;
        }

        if (vm.count("console")) {
            guest->set_system_call_filter(domain->system_call_filter(),
                                          SystemCallIndex::NtDeviceIoControlFile, true);
        }

        // Enable system call hooking on all vcpus
        domain->intercept_system_calls(true);

        // Create a thread to terminate our monitor after a timeout
        if (timeout != 0) {
            std::thread timeout_thread(wait_for_timeout, timeout);
            timeout_thread.detach();
        }

        // Start the poll
        ExecFileTool tool(*domain, process_name, target_file, arguments, working_directory,
                          vm.count("nowindow"), vm.count("exitcode"), vm.count("console"),
                          vm.count("admin"), session_id, syscall_monitor.get(),
                          vm.count("unsupported"));

        domain->poll(tool);

        return tool.result();
    } catch (TraceableException& ex) {
        std::cerr << ex;
        return 99;
    }
}

/**
 * Parse command line options here
 */
void parse_program_options(int argc, char** argv, po::options_description& desc,
                           po::variables_map& vm) {
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        /*
         * --help option
         */
        if (vm.count("help")) {
            std::cout << "ivexec - Execute a file in the guest" << '\n';
            std::cout << desc << '\n';
            exit(0);
        }

        po::notify(vm); // throws on error, so do after help in case
                        // there are any problems
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << desc << std::endl;
        exit(1);
    }
}
