![IntroVirt](.github/images/introvirt-logo.png)

## Description

IntroVirt, short for introspective virtualization, is a customized Hypervisor and library that provides a robust virtual machine introspection (VMI) application programming interface (API). VMI is the process of looking at the memory contents of a virtual machine during runtime. By applying knowledge of the guest operating system, introspection can be used for a variety of applications, including reverse engineering, debugging software, and securing guest VMs by limiting access to files or limiting an executing application’s functionality.

IntroVirt consists of three components: a patched version of the [KVM Hypervisor](https://github.com/IntroVirt/kvm-introvirt), the [IntroVirt userland library](https://github.com/IntroVirt/IntroVirt), and a Microsoft Program Database (MS PDB) parsing library [libmspdb](https://github.com/IntroVirt/libmspdb/tree/main).

## Quick start

![GitHub release (latest by date)](https://img.shields.io/github/v/release/IntroVirt/IntroVirt?color=brightgreen)

1. Navigate to the [releases](https://github.com/IntroVirt/IntroVirt/releases)
1. Download the appropriate IntroVirt `.zip` file for your Ubuntu distribution from the latest release
1. unzip the zip file, change into the `introvirt-ubuntu-xx.xx` folder and run: `sudo apt install ./*.deb`
1. Navigate to the [kvm-introvirt releases](https://github.com/IntroVirt/kvm-introvirt/releases) and download the file from the latest release that matches your kernel version (`uname -a`). If one does not exist, see the instructions in the [kvm-introvirt READEME.md](https://github.com/IntroVirt/kvm-introvirt) for how to build it yourself and please [submit an issue](https://github.com/IntroVirt/kvm-introvirt/issues) for support.
    * _We try to keep up with the latest kernel for each supported LTS. If you are behind, consider updating._
1. Unzip the `kvm-introvirt` zip file, change into the new directory and run: `sudo apt install ./*.deb`
1. Test: `sudo ivversion`

### Supported Kernels

| Ditro | Latest Supported Kernel | Status    |
| ----- | ----------------------- | --------- |
| 18.04 | [HWE 5.4.0-150-generic](https://github.com/IntroVirt/kvm-introvirt/releases)  | Supported |
| 20.04 | [HWE 5.15.0-119-generic](https://github.com/IntroVirt/kvm-introvirt/releases) | Supported |
| 22.04 | [HWE 6.5.0-35-generic](https://github.com/IntroVirt/kvm-introvirt/releases)   | Supported |
| 24.04 | [HWE 6.8.0-41-generic](https://github.com/IntroVirt/kvm-introvirt/releases)   | Supported |

## Building on Ubuntu Linux

First, build and install [libmspdb](https://github.com/IntroVirt/libmspdb) and [kvm-introvirt](https://github.com/IntroVirt/kvm-introvirt/)

Then, build from source:

```shell
sudo apt-get install -y \
    python3 python3-jinja2 cmake make build-essential libcurl4-openssl-dev libboost-dev \
    libboost-program-options-dev git clang-format liblog4cxx-dev libboost-stacktrace-dev \
    doxygen

git clone https://github.com/IntroVirt/IntroVirt.git
cd IntroVirt/build
cmake ..
make -j
```

Debian packages can then be built and installed (recommended):

```bash
make package
sudo apt install ./*.deb
```

Or `make` can be used directly to install:

```bash
sudo make install
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
    cd build
    make package
    ```
1. Make sure to `git add -u` and `git commit` the modification to the distro-specific changelog

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
