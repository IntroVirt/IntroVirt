![IntroVirt](.github/images/introvirt-logo.png)

[![Discord](https://dcbadge.limes.pink/api/server/https://discord.gg/YSdGvAhSmH?style=flat)](https://discord.gg/YSdGvAhSmH)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/IntroVirt/IntroVirt?color=brightgreen)](https://github.com/IntroVirt/IntroVirt/releases/latest)
[![CI Tests](https://github.com/IntroVirt/IntroVirt/actions/workflows/ci.yml/badge.svg)](https://github.com/IntroVirt/IntroVirt/actions/workflows/ci.yml)
[![Create Release](https://github.com/IntroVirt/IntroVirt/actions/workflows/release.yml/badge.svg)](https://github.com/IntroVirt/IntroVirt/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Github Pages](https://img.shields.io/badge/github%20pages-121013?style=&logo=github&logoColor=white)](https://introvirt.github.io/IntroVirt/)

## Description

IntroVirt, short for introspective virtualization, is a customized Hypervisor and library that provides a robust virtual machine introspection (VMI) application programming interface (API). VMI is the process of looking at the memory contents of a virtual machine during runtime. By applying knowledge of the guest operating system, introspection can be used for a variety of applications, including reverse engineering, debugging software, and securing guest VMs by limiting access to files or limiting an executing application’s functionality.

IntroVirt consists of three components: a patched version of the [KVM Hypervisor](https://github.com/IntroVirt/kvm-introvirt), the [IntroVirt userland library](https://github.com/IntroVirt/IntroVirt), and a Microsoft Program Database (MS PDB) parsing library [libmspdb](https://github.com/IntroVirt/libmspdb/tree/main).

## Quick start

1. Make sure SecureBoot is disabled on your system (you can also run IntroVirt nested in KVM)
    * _If someone wants to help me figure out a way around this please do!_
1. Download the latest [release](https://github.com/IntroVirt/IntroVirt/releases) for your Ubuntu version and install

    ```shell
    wget https://github.com/IntroVirt/IntroVirt/releases/latest/download/Ubuntu-$(lsb_release -sc)-$(lsb_release -sr).tar.xz
    tar -Jxvf Ubuntu-$(lsb_release -sc)-$(lsb_release -sr).tar.xz
    cd Ubuntu-$(lsb_release -sc)-$(lsb_release -sr)
    sudo apt install ./*.deb
    ```

1. Make sure all VMs on the current system are off before installing kvm-introvirt.
1. Download and install the latest [kvm-introvirt release](https://github.com/IntroVirt/kvm-introvirt/releases) that matches your kernel version (`uname -a`). If one does not exist, see the instructions in the [kvm-introvirt READEME.md](https://github.com/IntroVirt/kvm-introvirt) for how to build it yourself and please [submit an issue](https://github.com/IntroVirt/kvm-introvirt/issues) for support.
    * _We try to keep up with the latest kernel for each supported LTS. If you are behind, consider updating._

    ```shell
    wget https://github.com/IntroVirt/kvm-introvirt/releases/latest/download/kvm-introvirt-$(uname -r).$(lsb_release -sr)-1.0.0.deb
    sudo apt install ./kvm-introvirt-$(uname -r).$(lsb_release -sr)-1.0.0.deb
    ```

1. Test with: `sudo ivversion`
1. Get a live system call trace from a running Windows 10 VM: `sudo ivsyscallmon -D win10-22H2`
    * _This assumes you've installed a Windows 10 22H2 VM, named it "win10-22H2" and it is running._

![demo](./demo.gif)

### Supported Kernels

| Ditro | Latest Supported Kernel                                                       | Status    |
| ----- | ----------------------------------------------------------------------------- | ----------- |
| 18.04 | [HWE 5.4.0-150-generic](https://github.com/IntroVirt/kvm-introvirt/releases)  | EoL         |
| 20.04 | [HWE 5.15.0-119-generic](https://github.com/IntroVirt/kvm-introvirt/releases) | EoL         |
| 22.04 | [HWE 6.5.0-35-generic](https://github.com/IntroVirt/kvm-introvirt/releases)   | EoL         |
| 24.04 | [HWE 6.8.0-90-generic](https://github.com/IntroVirt/kvm-introvirt/releases)   | Supported   |
| 26.04 | coming soon                                                                   | Coming Soon |

### Supported Introspection Targets

IntroVirt is used to introspect a running virtual machine. The current release of IntroVirt supports Windows XP through Windows 10 22H2. Newer versions of Windows 10 may work, but you may experience unhandled exceptions in the user-land tools for changes to the Windows kernel that IntroVirt has not been updated for yet (hopefully soon though). Windows 11 is completely untested...so feel free to give it a try, though it will likely not work.

| OS         | Latest Supported Version | Status    |
| ---------- | ------------------------ | --------- |
| Windows XP | All                      | EoL       |
| Windows 7  | All                      | EoL       |
| Windows 10 | All                      | Supported |
| Windows 11 | 25H2                     | Partial   |

## Building on Ubuntu Linux

First, build and install [libmspdb](https://github.com/IntroVirt/libmspdb) and [kvm-introvirt](https://github.com/IntroVirt/kvm-introvirt/)

Then, build from source and install debs (python3-dev and swig are needed for optional Python bindings):

```shell
sudo apt-get install -y \
    python3 python3-jinja2 python3-dev swig cmake make build-essential libcurl4-openssl-dev \
    libboost-dev libboost-program-options-dev git clang-format liblog4cxx-dev \
    libboost-stacktrace-dev doxygen graphviz ninja-build

git clone https://github.com/IntroVirt/IntroVirt.git
cd IntroVirt/build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DDOXYGEN=ON -DINTROVIRT_PYTHON_BINDINGS=ON ..
ninja -j$(nproc) package
sudo apt install ./*.deb
```

Confirm everything is installed with: `sudo ivversion`

### Building deb package for release

_The deps for these steps can be installed with: `sudo apt install debhelper devscripts`_

1. If releasing a new version, bump the version number in `CMakeLists.txt` in these lines
    ```cmake
    SET(PACKAGE_MAJOR_VERSION #)
    SET(PACKAGE_MINOR_VERSION #)
    SET(PACKAGE_PATCH_VERSION #)
    ```
1. First copy the distro-specific files into place and update the changelog
    ```shell
    export DEBEMAIL="youremail@domain.com"
    cp ./debian/control.$(lsb_release -c -s 2> /dev/null) ./debian/control
    cp ./debian/changelog.$(lsb_release -c -s 2> /dev/null) ./debian/changelog
    dch -i # a message about what happened
    cp ./debian/changelog ./debian/changelog.$(lsb_release -c -s 2> /dev/null)
    ```
1. To build the `.deb` files
    ```shell
    ./scripts/build_release.sh
    ```
1. Make sure to `git add -u` and `git commit` the modification to the distro-specific changelog

## Usage Instructions

The included IntroVirt tools have their own usage instructions. See the `tools/` folder.

You can try system call monitoring with `sudo ivsyscallmon -D <domain>`. See `sudo ivsyscallmon --help` for more information.

## Resources

IntroVirt provides some useful resources to learn how to use it including:

- **Documentation**: [API reference (Doxygen)](https://introvirt.github.io/IntroVirt/) is built from the repo and published to GitHub Pages on push to `main`. To build locally: `cmake -G Ninja -DDOXYGEN=ON ..` then `ninja doc` (output in `build/html/`).
- **Examples**:
    * [IntroVirt Tools](./tools/) are great examples of the things you can do with IntroVirt.
    * [IntroVirt Examples](./examples/) are more verbosely documented and intended to be a good starting point.

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:

- **Chat**: https://discord.gg/YSdGvAhSmH
- **Issue Tracker**: https://github.com/IntroVirt/IntroVirt/issues

If you would like to help:

- **Pull Requests**: https://github.com/IntroVirt/IntroVirt/pulls
- **Contributing Guidelines**: https://github.com/IntroVirt/IntroVirt/blob/master/contributing.md

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
- **KVM-VMI:** https://github.com/KVM-VMI/kvm-vmi
- **Bitdefender:** https://github.com/bitdefender
- **HVMI**: https://github.com/hvmi/hvmi
- **libmicrovmi**: https://github.com/Wenzel/libmicrovmi
- **Drakvuf**: https://github.com/tklengyel/drakvuf
