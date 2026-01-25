; --- hypercall.asm ---
; Exported functions for invoking hypercalls to IntroVirt hypervisor to be used with
; the vmcall_interface example.
;
; Assemble with: llvm-ml -m64 -c hypercall.asm -o hypercall.obj

; This is the value, that will be stored in RAX, that is used to trigger IntroVirt hypercall handling.
; In the kvm-introvirt KVM patch, in the `kvm_emulate_hypercall` function, we check for this value and
; pass the event to IntroVirt for processing.
PUBLIC INTROVIRT_HYPERCALL_OPCODE
.data
INTROVIRT_HYPERCALL_OPCODE QWORD 0xFACE

; On Windows, the x64 calling convention (fastcall) uses:
; RCX, RDX, R8, R9 for the first four integer/pointer parameters.

; This invokes a hypercall to reverse a C-style string.
; Parameters:
;   RCX - Pointer to null-terminated C-style string
; Returns:
;   RAX - status code (e.g., 0 for success, non-zero for error)
.code
HypercallReverseCString PROC
    ; When invoking a hypercall, we need to set RAX to the hypercall opcode.
    ; The KVM IntroVirt patch checks for this value to identify IntroVirt hypercalls.
    mov rax, INTROVIRT_HYPERCALL_OPCODE

    ; Now we need to build our call to the running vmcall_interface tool
    ; The INTROVIRT_HYPERCALL_OPCODE triggers the vmcall to be sent as an event
    ; to any running IntroVirt tools. Then we need to pass our parameters.
    ;
    ; In this case we're passing 2 parameters:
    ;   1) RCX: The service code = CSTRING_REVERSE (0xF000) (reverse C-string)
    ;   2) RDX: c_str = pointer to C-style string
    ;
    ; This helper functions takes only the c_str parameter, so we need to
    ; move the c_str pointer into RDX, and set RCX to the service code.
    mov rdx, rcx      ; Move c_str pointer to RDX
    mov rcx, 0xF000   ; CSTRING_REVERSE service code
    vmcall            ; Transition to the hypervisor (make the hypercall)

    ; The status code (0 or non-zero) is returned in RAX.
    ; Since RAX is the standard return register, we just return.
    ret
HypercallReverseCString ENDP

HypercallWriteProtectMemory PROC
    ; When invoking a hypercall, we need to set RAX to the hypercall opcode.
    ; The KVM IntroVirt patch checks for this value to identify IntroVirt hypercalls.
    mov rax, INTROVIRT_HYPERCALL_OPCODE

    ; Now we need to build our call to the running vmcall_interface tool
    ; The INTROVIRT_HYPERCALL_OPCODE triggers the vmcall to be sent as an event
    ; to any running IntroVirt tools. Then we need to pass our parameters.
    ;
    ; In this case we're passing 3 parameters:
    ;   1) RCX: The service code = WRITE_PROTECT (0xF001) (write-protect memory)
    ;   2) RDX: buffer = pointer to a buffer
    ;   3) R8:  length = length of the buffer
    ;
    ; This helper functions takes only the buffer and the length parameter, so we need to
    ; move some things around to set up the registers correctly.
    mov r8, rdx       ; Move length to R8
    mov rdx, rcx      ; Move buffer pointer to RDX
    mov rcx, 0xF001   ; WRITE_PROTECT service code
    vmcall            ; Transition to the hypervisor (make the hypercall)

    ; The status code (0 or non-zero) is returned in RAX.
    ; Since RAX is the standard return register, we just return.
    ret
END
