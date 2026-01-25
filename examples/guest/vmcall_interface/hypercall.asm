; --- hypercall.asm ---
; Assemble with: llvm-ml -m64 -c hypercall.asm -o hypercall.obj

.code

; InvokeHypercall(u64 control_code, u64 input_ptr, u64 output_ptr)
; Register mapping (x64 fastcall):
; RCX = control_code
; RDX = input_ptr
; R8  = output_ptr
HypercallReverseCString PROC
    ; Most hypervisors (like Hyper-V) expect the parameters
    ; in exactly these registers for the VMCALL instruction.

    mov rax, rcx      ; Move control_code to RAX
    vmcall            ; Transition to the hypervisor

    ; The status code (e.g., HV_STATUS_SUCCESS) is returned in RAX.
    ; Since RAX is the standard return register, we just return.
    ret
HypercallReverseCString ENDP

HypercallWriteProtectMemory PROC
    ; Most hypervisors (like Hyper-V) expect the parameters
    ; in exactly these registers for the VMCALL instruction.

    mov rax, rcx      ; Move control_code to RAX
    vmcall            ; Transition to the hypervisor

    ; The status code (e.g., HV_STATUS_SUCCESS) is returned in RAX.
    ; Since RAX is the standard return register, we just return.
    ret
END
