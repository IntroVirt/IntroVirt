# Example documentation {#examples_doc}

This page describes the C++ example programs and tools included with IntroVirt. The main instructional example is **vmcall_interface**, which shows how to implement a custom hypercall interface between a Windows guest and an IntroVirt tool.

For Python examples and tools (ivsyscallmon, ivcallmon, ivfilemon), see the [Python documentation](python/index.html).

Example **source files** (marked with `@example` in code) are listed in the **Examples** menu in the navigation; each entry links to the full source. Use this page for walkthroughs, build, and usage; use the Examples list for the actual code.

---

## vmcall_interface

**Source:**

<div class="tabbed">

- <b class="tab-title">C++</b> \ref vmcall_interface.cc — listed in the **Examples** menu.
- <b class="tab-title">Python</b> \ref vmcall_interface.py — listed in the **Examples** menu.

</div>

The vmcall_interface example demonstrates using the x86 `vmcall` instruction to communicate between a process running inside a Windows guest and an IntroVirt tool running on the host. The guest requests services (reverse a string, write-protect memory, protect the process) by executing `vmcall` with a service code; the hypervisor delivers the event to the IntroVirt tool, which performs the action and returns a status in `RAX`.

A Python port of the host tool is also available (`examples/vmcall_interface.py`); it uses the raw IntroVirt Python bindings (not pyintrovirt helpers) and implements the same three services.

There are two components:

| Component | Location | Role |
|-----------|----------|------|
| **Host tool** | `examples/vmcall_interface` (built with IntroVirt) | Attaches to the VM, handles hypercall and system-call events, implements the services. |
| **Guest executable** | `examples/guest/vmcall_interface` (build on Windows) | Runs inside the VM and issues `vmcall` to request each service. |

### Architecture overview

1. Guest code sets **RAX = 0xFACE** (IntroVirt hypercall opcode), **RCX** = service code, and optional args in **RDX**, **R8**, **R9**, then executes `vmcall`.
2. The KVM IntroVirt kernel patch recognizes the hypercall and delivers an **EVENT_HYPERCALL** to the IntroVirt tool.
3. The tool's event callback (\ref introvirt::EventCallback) reads registers, dispatches on the service code, and implements the action (e.g. reverse string in guest memory, create a watchpoint).
4. The tool sets **RAX** to a return code and returns; execution resumes in the guest with that return value.

Service codes used in this example:

| Code | Name | Description |
|------|------|--------------|
| `0xF000` | CSTRING_REVERSE | Reverse a C-string in place (pointer in RDX). |
| `0xF001` | WRITE_PROTECT | Make a memory region read-only (buffer in RDX, length in R8). |
| `0xF002` | PROTECT_PROCESS | Protect the calling process from termination, injection, and debugging. |

**System call filtering (Windows):** For Windows guests, enable the filter at the domain level (`domain.system_call_filter().enabled(true)`) and set which syscalls to trap at the guest level via `WindowsGuest.set_system_call_filter(domain.system_call_filter(), SystemCallIndex_XXX, true)`. Do not call `set_64` or `set_32` on the domain filter; the guest converts `SystemCallIndex` to native indices. This matches **ivfilemon**, **ivcallmon**, and **vmcall_interface**.

---

### Host side: IntroVirt tool

The host tool attaches to a domain, detects a Windows guest, enables system-call interception for **NtTerminateProcess** and **NtOpenProcess** (for cleanup and process protection), then polls for events. Hypercalls are handled in `EventHandler::handle_hypercall()`; system calls are used to clean up watchpoints on exit and to enforce process protection.

#### Attaching and starting the event loop

<div class="tabbed">

- <b class="tab-title">C++</b>
  ```cpp
  auto hypervisor = Hypervisor::instance();
  domain = hypervisor->attach_domain(domain_name);  // by name or PID

  signal(SIGINT, &sig_handler);
  if (!domain->detect_guest()) { /* error */ }
  if (domain->guest()->os() != OS::Windows) { /* this example is Windows-only */ }

  auto* guest = static_cast<WindowsGuest*>(domain->guest());
  guest->set_system_call_filter(domain->system_call_filter(),
      SystemCallIndex::NtTerminateProcess, true);
  guest->set_system_call_filter(domain->system_call_filter(),
      SystemCallIndex::NtOpenProcess, true);
  domain->system_call_filter().enabled(true);
  domain->intercept_system_calls(true);

  domain->poll(event_handler);  // blocks; events go to EventHandler::process_event
  ```

- <b class="tab-title">Python</b>
  ```python
  hypervisor = introvirt.Hypervisor.instance()
  domain = hypervisor.attach_domain(domain_name)  # by name or PID

  if not domain.detect_guest():
      raise RuntimeError("Failed to detect guest")
  if domain.guest().os() != introvirt.OS_Windows:
      raise RuntimeError("Windows guest required")

  win_guest = introvirt.WindowsGuest_from_guest(domain.guest())
  win_guest.set_system_call_filter(
      domain.system_call_filter(), introvirt.SystemCallIndex_NtTerminateProcess, True)
  win_guest.set_system_call_filter(
      domain.system_call_filter(), introvirt.SystemCallIndex_NtOpenProcess, True)
  domain.system_call_filter().enabled(True)
  domain.intercept_system_calls(True)

  domain.poll(handler)  # blocks; events go to handler.process_event
  ```

</div>

#### Handling hypercalls

The callback receives **EVENT_HYPERCALL**, then reads the service code from **RCX** and dispatches:

<div class="tabbed">

- <b class="tab-title">C++</b>
  ```cpp
  void handle_hypercall(Event& event) {
      auto& regs = event.vcpu().registers();
      // Log: process name, PID:TID, RIP, RAX, RCX, RDX, R8, R9

      int return_code = 1;
      switch (regs.rcx()) {
      case CSTRING_REVERSE:
          return_code = service_string_reverse(event);
          break;
      case WRITE_PROTECT:
          return_code = service_write_protect(event);
          break;
      case PROTECT_PROCESS:
          return_code = service_protect_process(event);
          break;
      default:
          return_code = 1;  // unknown service
      }
      regs.rax(return_code);  // return value to guest
  }
  ```

- <b class="tab-title">Python</b>
  ```python
  def _handle_hypercall(self, event):
      task = event.task()
      vcpu = event.vcpu()
      regs = vcpu.registers()
      return_code = 1
      if regs.rcx() == CSTRING_REVERSE:
          return_code = self._service_string_reverse(event)
      elif regs.rcx() == WRITE_PROTECT:
          return_code = self._service_write_protect(event)
      elif regs.rcx() == PROTECT_PROCESS:
          return_code = self._service_protect_process(event)
      rax_val = return_code if return_code >= 0 else (1 << 64) + return_code
      introvirt.set_register_rax(regs, rax_val)
  ```

</div>

#### Service: reverse string (CSTRING_REVERSE)

The guest passes a pointer to a C-string in **RDX**. The tool reads the string from guest memory, reverses it in place, and returns 0 on success:

<div class="tabbed">

- <b class="tab-title">C++</b>
  ```cpp
  int service_string_reverse(Event& event) {
      auto& regs = event.vcpu().registers();
      try {
          guest_ptr<void> pStr(event.vcpu(), regs.rdx());
          guest_ptr<char[]> str = map_guest_cstring(pStr);
          reverse(str.begin(), str.end());
          return 0;
      } catch (VirtualAddressNotPresentException& ex) {
          return -1;
      }
  }
  ```

- <b class="tab-title">Python</b>
  ```python
  def _service_string_reverse(self, event) -> int:
      vcpu = event.vcpu()
      addr = vcpu.registers().rdx()
      try:
          s = introvirt.read_guest_cstring(self._domain, vcpu, addr)
          rev = s[::-1]
          introvirt.write_guest_bytes(self._domain, vcpu, addr, rev.encode() + b"\x00")
          return 0
      except Exception:
          return -1
  ```

</div>

#### Service: write-protect memory (WRITE_PROTECT)

The guest passes a buffer pointer in **RDX** and length in **R8**. The tool creates a watchpoint for writes to that region; on write it injects a fault. Watchpoints are stored per-PID and removed when the process exits (via **NtTerminateProcess** handling):

<div class="tabbed">

- <b class="tab-title">C++</b>
  ```cpp
  int service_write_protect(Event& event) {
      auto& regs = event.vcpu().registers();
      guest_ptr<void> pBuffer(event.vcpu(), regs.rdx());
      uint64_t length = regs.r8();

      auto wp = domain->create_watchpoint(
          pBuffer, length, false, true, false,
          [this](Event& e) { memory_access_violation(e); });
      read_only_protections_[event.task().pid()].push_back(std::move(wp));
      return 0;
  }
  ```

- <b class="tab-title">Python</b>
  ```python
  def _service_write_protect(self, event) -> int:
      vcpu = event.vcpu()
      regs = vcpu.registers()
      addr, length = regs.rdx(), regs.r8()
      if length == 0:
          return -1
      wp = introvirt.create_watchpoint(
          self._domain, vcpu, addr, length,
          read=False, write=True, execute=False,
          callback=self._wp_callback,
      )
      if wp is not None:
          pid = event.task().pid()
          self._watchpoints.setdefault(pid, []).append(wp)
          return 0
      return -1
  ```

</div>

#### Service: protect process (PROTECT_PROCESS)

The tool adds the calling process's PID to a protected set. In **NtTerminateProcess** it blocks termination of that PID; in **NtOpenProcess** it blocks opening the process with terminate/write/debug rights.

<div class="tabbed">

- <b class="tab-title">C++</b>
  ```cpp
  int service_protect_process(Event& event) {
      protected_pids_.insert(event.task().pid());
      return 0;
  }
  // NtTerminateProcess / NtOpenProcess handlers enforce the protected set.
  ```

- <b class="tab-title">Python</b>
  ```python
  def _service_protect_process(self, event) -> int:
      self._protected_pids.add(event.task().pid())
      return 0
  # _handle_syscall blocks NtTerminateProcess/NtOpenProcess for protected PIDs.
  ```

</div>

---

### Guest side: making the vmcall

On x64 Windows the first four integer/pointer arguments use **RCX**, **RDX**, **R8**, **R9**. The IntroVirt KVM patch treats a `vmcall` as an IntroVirt hypercall when **RAX == 0xFACE**. The guest assembler sets **RAX**, **RCX** (and **RDX**/ **R8**/ **R9** as needed), then executes `vmcall`; the return status is in **RAX**.

#### Assembler: hypercall stub (vmcall.asm)

```asm
; RAX = 0xFACE identifies the call to IntroVirt.
; RCX = service code; RDX, R8, R9 = arguments (per service).

HypercallReverseCString PROC
    mov rax, 0FACEh
    mov rdx, rcx      ; c_str pointer in RDX
    mov rcx, 0F000h   ; CSTRING_REVERSE
    vmcall
    ret
HypercallReverseCString ENDP

HypercallWriteProtectMemory PROC
    mov rax, 0FACEh
    mov r8, rdx       ; length in R8
    mov rdx, rcx      ; buffer in RDX
    mov rcx, 0F001h   ; WRITE_PROTECT
    vmcall
    ret
HypercallWriteProtectMemory ENDP

HypercallProtectProcess PROC
    mov rax, 0FACEh
    mov rcx, 0F002h   ; PROTECT_PROCESS
    vmcall
    ret
HypercallProtectProcess ENDP
```

Assemble with LLVM (e.g. `llvm-ml -m64 -c vmcall.asm -o vmcall.obj`).

#### Guest C code (main.c)

The C side declares the assembler functions and uses them for each demo:

```c
extern uint64_t HypercallReverseCString(char *c_str);
extern uint64_t HypercallWriteProtectMemory(void* buffer, uint64_t length);
extern uint64_t HypercallProtectProcess();

int reverse_string() {
    char test_str[] = "Hello, IntroVirt!";
    uint64_t status = HypercallReverseCString(test_str);
    if (status == 0)
        printf("Reversed string: %s\n", test_str);
    return status;
}

int mem_protect() {
    uint8_t *buffer = (uint8_t*)malloc(BUFFER_SIZE);
    HypercallWriteProtectMemory(buffer, BUFFER_SIZE);
    // Next write to buffer triggers access violation in guest
    for (size_t i = 0; i < BUFFER_SIZE; i++)
        buffer[i] = 'B';  // fault here if protection is active
    // ...
}

int protect_process() {
    HypercallProtectProcess();
    // Process cannot be terminated or debugged by others; Ctrl+C to exit
    while (running) { Sleep(100); }
    return 0;
}
```

---

### Building

#### Host tool (Linux, as part of IntroVirt)

<div class="tabbed">

- <b class="tab-title">C++</b>
  The vmcall_interface binary is built with IntroVirt. From the project root:

  ```bash
  mkdir -p build && cd build
  cmake -DCMAKE_BUILD_TYPE=Release ..
  make -j
  # or: ninja
  ```

  The executable is `build/examples/vmcall_interface`.

- <b class="tab-title">Python</b>
  No separate build step is required beyond building IntroVirt with Python bindings enabled (`-DINTROVIRT_PYTHON_BINDINGS=ON`). The script is `examples/vmcall_interface.py`; run it with `PYTHONPATH=./python` pointing at the build output (see Usage below).

</div>

#### Guest executable (Windows)

Build the guest code on a Windows VM with Clang/LLVM on the path (e.g. from [LLVM releases](https://github.com/llvm/llvm-project/releases)).

1. Copy the guest example into the VM:
   - `examples/guest/vmcall_interface/build.ps1`
   - `examples/guest/vmcall_interface/vmcall.asm`
   - `examples/guest/vmcall_interface/main.c`

2. From that directory in PowerShell:

```powershell
.\build.ps1
# Produces .\bin\vmcall_test.exe
```

---

### Usage

1. **Start the VM** (e.g. a Windows guest) and ensure the guest has `vmcall_test.exe` (or equivalent) available. Do not run it yet.

2. **Start the IntroVirt tool** on the host, attaching by domain name or PID:

<div class="tabbed">

- <b class="tab-title">C++</b>
  ```bash
  cd build
  sudo ./examples/vmcall_interface -D win10
  # Or by domain PID: sudo ./examples/vmcall_interface -D 12345
  ```

- <b class="tab-title">Python</b>
  ```bash
  cd build
  sudo PYTHONPATH=./python python3 ../examples/vmcall_interface.py win10
  # Or by domain PID: sudo PYTHONPATH=./python python3 ../examples/vmcall_interface.py 12345
  ```

</div>

Leave this running. You should see it attach and detect the Windows guest.

3. **Run the guest executable** inside the VM with one of the three commands:

| Guest command | What it does |
|----------------|--------------|
| `vmcall_test.exe reverse-string` | Reverses the string `"Hello, IntroVirt!"` in place via hypercall; prints original and reversed. |
| `vmcall_test.exe mem-protect` | Asks the hypervisor to write-protect a buffer, then writes to it; the write triggers a fault and the program will crash (access violation) if protection is active. Use Ctrl+C to exit. |
| `vmcall_test.exe protect-process` | Marks the process as protected. The hypervisor blocks termination and opening the process with dangerous rights; the process cannot be killed or debugged by other guest programs. Use Ctrl+C in the **host** vmcall_interface terminal to stop the tool and detach; then the guest process will exit. |

4. **Stop the host tool** with Ctrl+C in the terminal where `vmcall_interface` is running so it can detach cleanly from the domain.

---

### Summary

- **vmcall_interface** shows a full hypercall-based "API" between a Windows guest and an IntroVirt tool: guest uses **RAX=0xFACE**, **RCX**=service code, **RDX/R8/R9**=arguments, then `vmcall`; the host handles **EVENT_HYPERCALL** and returns status in **RAX**.
- It also uses system-call interception (**NtTerminateProcess**, **NtOpenProcess**) to clean up state and to enforce process protection, illustrating how to combine hypercalls with Windows system-call filtering in one tool.

For the full source, see \ref vmcall_interface.cc (C++) or \ref vmcall_interface.py (Python), and `examples/guest/vmcall_interface/` for the guest executable.
