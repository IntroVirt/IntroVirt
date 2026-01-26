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
#include <string.h>
#include <windows.h>

// Tell the compiler this function exists in another file (hypercall.obj)
extern uint64_t HypercallReverseCString(char *c_str);
extern uint64_t HypercallWriteProtectMemory(void* buffer, uint64_t length);
extern uint64_t HypercallProtectProcess();

int main(int argc, char** argv) {
    uint64_t status = 0;

    if (argc != 2) {
        printf("Usage: %s [reverse-string|mem-protect|protect-process]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "reverse-string") == 0) {
        char test_str[] = "Hello, IntroVirt!";
        printf("Original string: %s\n", test_str);

        // Call the hypercall to reverse the string
        status = HypercallReverseCString(test_str);
        if (status == 0) {
            printf("Reversed string: %s\n", test_str);
        } else {
            printf("Failed to reverse string, status code: %llu\n", status);
        }
    } else if (strcmp(argv[1], "mem-protect") == 0) {
        // Now demonstrate write-protecting a memory region
        char buffer[] = "This buffer will be write-protected.";
        printf("Original buffer: %s\n", buffer);
        status = HypercallWriteProtectMemory(buffer, sizeof(buffer));
        if (status == 0) {
            printf("Buffer write-protected successfully.\n");
        } else {
            printf("Failed to write-protect buffer, status code: %llu\n", status);
        }
    } else if (strcmp(argv[1], "protect-process") == 0) {
        status = HypercallProtectProcess();
        if (status == 0) {
            while (1) {
                printf("This process is protected. You can't do anything!!!");
                Sleep(2);
            }
        } else {
            printf("Failed to protect the process: %llu\n", status);
        }
    }

    return 0;
}
