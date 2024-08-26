![IntroVirt](.github/images/introvirt-logo.png)

## Description

IntroVirt, short for introspective virtualization, is a customized Hypervisor and library that provides a robust virtual machine introspection (VMI) application programming interface (API). VMI is the process of looking at the memory contents of a virtual machine during runtime. By applying knowledge of the guest operating system, introspection can be used for a variety of applications, including reverse engineering, debugging software, and securing guest VMs by limiting access to files or limiting an executing application’s functionality.

IntroVirt consists of three components: a patched version of the [KVM Hypervisor](https://github.com/IntroVirt/kvm-introvirt), the [IntroVirt userland library](https://github.com/IntroVirt/IntroVirt), and a Microsoft Program Database (MS PDB) parsing library [libmspdb](https://github.com/IntroVirt/libmspdb/tree/main).

## Quick start

![GitHub release (latest by date)](https://img.shields.io/github/v/release/IntroVirt/IntroVirt?color=brightgreen)

Soon!

## Building on Ubuntu Linux

1. Install build dependencies:
    ```shell
    sudo apt update && \
    sudo apt-get install -y \
        python3 python3-jinja2 cmake make build-essential libcurl4-openssl-dev libboost-dev \
        libboost-program-options-dev git clang-format liblog4cxx-dev
    ```
1. Build and install `libmspdb`
    ```shell
    git clone https://github.com/IntroVirt/libmspdb.git
    cd libmspdb/build/
    cmake ..
    make -j
    sudo make install
    ```
1. Build and install IntroVirt:
    ```shell
    git clone https://github.com/IntroVirt/IntroVirt.git
    cd IntroVirt/build
    cmake ..
    make -j
    sudo make install
    ```
1. Build and install [kvm-introvirt](https://github.com/IntroVirt/kvm-introvirt/)
1. Confirm: `sudo ivversion`

### Post-install steps

TODO: Create introvirt group, add yourself to it, `newgrp`, mark introvirt tool binaries setuid and owned by root/introvirt

## Usage Instructions

The included IntroVirt tools have their own usage instructions. See the `tools/` folder.

You can try system call monitoring with `sudo ivsyscallmon -D <domain>`. See `sudo ivsyscallmon --help` for more information.

## Resources

IntroVirt provides some useful resources to learn how to use it including:

- **Documentation**: TBD
- **Examples**: TBD
- **Unit Tests**: TBD

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:

- **Chat**: TBD
- **Issue Tracker**: <https://github.com/IntroVirt/IntroVirt/issues>

If you would like to help:

- **Pull Requests**: <https://github.com/IntroVirt/IntroVirt/pulls>
- **Contributing Guidelines**: <https://github.com/IntroVirt/IntroVirt/blob/master/contributing.md>

## License

IntroVirt is licensed under the Apache v2.0 License.

## Interested In Working For AIS?

Check out our [Can You Hack It?®](https://www.canyouhackit.com) challenge and test your skills! Submit your score to show us what you’ve got. We have offices across the country and offer competitive pay and outstanding benefits. Join a team that is not only committed to the future of cyberspace, but to our employee’s success as well.

<p align="center">
  <a href="https://www.ainfosec.com/">
    <img src="https://github.com/IntroVirt/IntroVirt/raw/main/.github/images/ais.png" alt="ais" height="100" />
  </a>
</p>

## Related

If you’re interested in IntroVirt, you might also be interested in the
following projects:

- **LibVMI:** https://github.com/libvmi/libvmi
- **Bitdefender:** ttps://github.com/bitdefender
- **HVMI**: https://github.com/hvmi/hvmi
- **libmicrovmi**: https://github.com/Wenzel/libmicrovmi
