/*
 * main.c
 *
 * This file contains example code to perform a hypercall (VMCALL)
 * from within a Windows guest. It defines functions `HypercallReverseCString`
 * and `HypercallWriteProtectMemory` that make hypercalls to the hypervisor.
 *
*/
#include <stdio.h>
#include <stdint.h>

// This is the value, that will be stored in RAX, that is used to trigger IntroVirt hypercall handling.
// In the kvm-introvirt KVM patch, in the  `kvm_emulate_hypercall` function, we check for this value and
// pass the event to IntroVirt for processing.
#define INTROVIRT_HYPERCALL_OPCODE 0xFACE

// Tell the compiler this function exists in another file (hypercall.obj)
extern uint64_t HypercallReverseCString(uint64_t control_code, uint64_t input_gpa, uint64_t output_gpa);
extern uint64_t HypercallWriteProtectMemory(uint64_t control_code, uint64_t input_gpa, uint64_t output_gpa);

int main() {
    printf("Invoking hypercall...\n");
    //uint64_t status = InvokeHypercall(0xFACE, 0, 0);
    printf("Hypercall returned status: 0x%llx\n", status);
    return 0;
}
