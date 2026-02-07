# Examples

TODO

## vmcall_interface.c

This example demonstrates using `vmcall` instructions to communicate with an IntroVirt tool. There are 2 components: the tool (`vmcall_interface`), and the guest executable (`vmcall_test.exe`). The IntroVirt tool is built as part of the IntroVirt build process. The guest tool must be built on Windows using the `build.ps1` script with `llvm` installed and on the path.

### Guest Tool Deps

* The code for the guest tool is in `./examples/guest/vmcall_interface`
* Copy the `build.ps1`, `vmcall.asm`, and `main.c` files to a Windows guest VM and build inside the guest
* Clang/LLVM must be installed and on the path
    * https://github.com/llvm/llvm-project/releases/

### Guest Tool Build

```powershell
# This will output ./bin/vmcall_test.exe
.\build.ps1
```

### Usage

1. Start the IntroVirt tool and point it at a running guest with the example executable inside but not yet running:
    ```bash
    # Assuming the VM label is "win10"
    cd ./build
    sudo ./examples/vmcall_interface -Dwin10
    ```
1. Now, run the test tool in the guest with different arguments to see the functionality.
    ```powershell
    # Should print a string, and then a reverse of the string.
    vmcall_test.exe reverse-string

    # Should crash with an access violation
    vmcall_test.exe mem-protect

    # Should protect the guest process - won't be possible to kill or debug. Cntrl+c to exit
    vmcall_test.exe protect-process
    ```
