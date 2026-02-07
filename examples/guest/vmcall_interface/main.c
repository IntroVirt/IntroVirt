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
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>

#define BUFFER_SIZE 64

// Tell the compiler this function exists in another file (hypercall.obj)
extern uint64_t HypercallReverseCString(char *c_str);
extern uint64_t HypercallWriteProtectMemory(void* buffer, uint64_t length);
extern uint64_t HypercallProtectProcess();

// Function prototypes for the demo functions
int reverse_string();
int mem_protect();
int protect_process();

static bool running = true;

void signal_handler(int _signum) {
    printf("Caught cntrl+c, exiting...\n");
    running = false;
}

int main(int argc, char** argv) {
    uint64_t status = 0;

    if (argc != 2) {
        printf("Usage: %s [reverse-string|mem-protect|protect-process]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, signal_handler);

    if (strcmp(argv[1], "reverse-string") == 0) {
        return reverse_string();
    } else if (strcmp(argv[1], "mem-protect") == 0) {
        return mem_protect();
    } else if (strcmp(argv[1], "protect-process") == 0) {
        return protect_process();
    }

    printf("Unknown command: %s\n", argv[1]);
    return 1;
}

/*
 * Called to demonstrate reversing a string via hypercall.
 * The hypervisor will reverse the string in place.
 */
int reverse_string() {
    char test_str[] = "Hello, IntroVirt!";
    printf("Original string: %s\n", test_str);

    // Call the hypercall to reverse the string
    uint64_t status = HypercallReverseCString(test_str);
    if (status == 0) {
        printf("Reversed string: %s\n", test_str);
    } else {
        printf("Failed to reverse string, status code: %llu\n", status);
    }
    return status;
}

/*
 * Called to demonstrate write-protecting a memory buffer via hypercall.
 * The hypervisor will set the memory region to read-only and enforce it.
 */
int mem_protect() {
    uint8_t *buffer = (uint8_t*)malloc(BUFFER_SIZE);
    if (!buffer) {
        printf("Failed to allocate memory buffer.\n");
        return 1;
    }
    memset(buffer, 'A', BUFFER_SIZE);

    printf("Buffer before write-protect:\n");
    for (size_t i = 0; i < BUFFER_SIZE; i++) {
        printf("%c", buffer[i]);
    }
    printf("\n");

    // Call the hypercall to write-protect the memory buffer
    uint64_t status = HypercallWriteProtectMemory(buffer, BUFFER_SIZE);
    if (status != 0) {
        printf("Failed to write-protect memory, status code: %llu\n", status);
        return status;
    }

    // Attempt to modify the protected buffer
    printf("Attempting to modify the protected buffer...\n");
    for (size_t i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = 'B';  // This should result in an access violation
    }

    // The program shouldn't make it here if the protection worked
    printf("Buffer after attempted modification:\n");
    for (size_t i = 0; i < BUFFER_SIZE; i++) {
        printf("%c", buffer[i]);
    }
    printf("\n");

    printf("Cntrl+c to exit the demo...\n");
    while (running) {
        Sleep(100);
    }
    return 0;
}

/*
 * Called to demonstrate protecting the entire process via hypercall.
 * The hypervisor will enforce protection on the process memory and execution.
 * It will prevent the process from being terminated, modified, or debugged.
 */
int protect_process() {
    // Call the hypercall to protect the entire process
    uint64_t status = HypercallProtectProcess();
    if (status != 0) {
        printf("Failed to protect process, status code: %llu\n", status);
        return status;
    }

    printf("Process memory is now protected by the hypervisor.\n");
    while (running) {
        printf("This process is protected. You can't do anything! cntrl+c to quit...nothing else will kill us!!!\n");
        Sleep(100);
    }
    return 0;
}
