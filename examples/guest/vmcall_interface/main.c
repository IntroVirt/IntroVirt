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

// Tell the compiler this function exists in another file (hypercall.obj)
extern uint64_t HypercallReverseCString(char *c_str);
extern uint64_t HypercallWriteProtectMemory(void* buffer, uint64_t length);

int main() {
    char test_str[] = "Hello, IntroVirt!";
    printf("Original string: %s\n", test_str);

    // Call the hypercall to reverse the string
    uint64_t status = HypercallReverseCString(test_str);
    if (status == 0) {
        printf("Reversed string: %s\n", test_str);
    } else {
        printf("Failed to reverse string, status code: %llu\n", status);
    }

    // Now demonstrate write-protecting a memory region
    char buffer[] = "This buffer will be write-protected.";
    printf("Original buffer: %s\n", buffer);
    status = HypercallWriteProtectMemory(buffer, sizeof(buffer));
    if (status == 0) {
        printf("Buffer write-protected successfully.\n");
    } else {
        printf("Failed to write-protect buffer, status code: %llu\n", status);
    }

    return 0;
}
