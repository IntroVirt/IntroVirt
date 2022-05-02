![IntroVirt](.github/images/introvirt-logo.png)

## Description

IntroVirt, short for introspective virtualization, is a customized Hypervisor and library that provides a robust virtual machine introspection (VMI) application programming interface (API). VMI is the process of looking at the memory contents of a virtual machine during runtime. By applying knowledge of the guest operating system, introspection can be used for a variety of applications, including reverse engineering, debugging software, and securing guest VMs by limiting access to files or limiting an executing application’s functionality.

IntroVirt consists of two components: a patched version of the [KVM Hypervisor](https://github.com/IntroVirt/kvm-introvirt), and the [IntroVirt userland library](https://github.com/IntroVirt/IntroVirt).

## **Quick start**
![GitHub release (latest by date)](https://img.shields.io/github/v/release/IntroVirt/IntroVirt?color=brightgreen)

First, we need to get on the same kernel version supported by kvm-introvirt, which is currently Ubuntu Focal's `5.4.0-x`:
```
$ uname -r
5.4.0-109-generic
```

On Ubuntu 20.04 (Focal), we can revert to the Linux kernel version `5.4.0-x` by [disabling HWE](https://wiki.ubuntu.com/Kernel/LTSEnablementStack#Ubuntu_20.04_LTS_-_Focal_Fossa). The latest security patches are still provided by Canonical. To check if HWE is enabled, we can run `hwe-support-status` (no output means disabled, otherwise HWE is enabled).

To install on Ubuntu focal from the latest Github release.
```
mkdir introvirt_pkgs && cd introvirt_pkgs
wget https://github.com/IntroVirt/kvm-introvirt/releases/latest/download/kvm-introvirt.zip
wget https://github.com/IntroVirt/libmspdb/releases/latest/download/libmspdb.zip
wget https://github.com/IntroVirt/IntroVirt/releases/latest/download/introvirt.zip
unzip *.zip
sudo apt install *.deb
```

We will need to be booted into the correct kernel, based on the latest version of kvm-introvirt.
If properly configured, running `sudo ivversion` will return a supported hypervisor.

## Interested In Working For AIS?
Check out our [Can You Hack It?®](https://www.canyouhackit.com) challenge and test your skills! Submit your score to show us what you’ve got. We have offices across the country and offer competitive pay and outstanding benefits. Join a team that is not only committed to the future of cyberspace, but to our employee’s success as well.

<p align="center">
  <a href="https://www.ainfosec.com/">
    <img src="https://github.com/IntroVirt/IntroVirt/raw/main/.github/images/ais.png" alt="ais" height="100" />
  </a>
</p>

### **Building on Ubuntu Linux**

Install build dependencies:

If using the launchpad PPA, libmspdb-dev can be installed as a package:
```
sudo apt-get install cmake libcurl4-openssl-dev libboost-dev libboost-program-options-dev libboost-stacktrace-dev liblog4cxx-dev libmspdb-dev python3-jinja2 python3 doxygen clang-format git
```

Otherwise, build and install libmspdb
```
sudo apt-get -y cmake libcurl4-openssl-dev libboost-dev git
git clone https://github.com/IntroVirt/libmspdb.git
cd libmspdb/build/
cmake ..
make
sudo make install
```
Note: You will also have to build and install [kvm-introvirt](https://github.com/IntroVirt/kvm-introvirt/) if not using the PPA.

Build and install IntroVirt:
```
cd build
cmake ..
make
sudo make install
```

## Building a source package for Launchpad ##

First you'll need to copy the distro specific files into place:
```
cd debian/
cp control.focal control
cp changelog.focal changelog
dch -i # Bump the package version
cp changelog changelog.focal
cd ..
```

Next, build the source package:
```
debuild -S -sa
```

Finally, upload to launchpad
```
dput ppa:<ppa name> introvirt_<version>_source.changes 
```

## Usage Instructions
The included IntroVirt tools have their own usage instructions. See the `tools/` folder.

You can try system call monitoring with `sudo ivsyscallmon -D <domain>`. See `sudo ivsyscallmon --help` for more information.

## **Resources**
IntroVirt provides some useful resources to learn how to use it including:
-   **Documentation**: TBD
-   **Examples**: TBD
-   **Unit Tests**: TBD

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:
-   **Chat**: TBD
-   **Issue Tracker**: <https://github.com/IntroVirt/IntroVirt/issues>

If you would like to help:
-   **Pull Requests**: <https://github.com/IntroVirt/IntroVirt/pulls>
-   **Contributing Guidelines**: <https://github.com/IntroVirt/IntroVirt/blob/master/contributing.md>

## License
IntroVirt is licensed under the Apache v2.0 License.

## Related
If you’re interested in IntroVirt, you might also be interested in the
following projects:

**LibVMI:** <br>
https://github.com/libvmi/libvmi

**Bitdefender:**  <br>
https://github.com/bitdefender

**HVMI:**  <br>
https://github.com/hvmi/hvmi

**libmicrovmi:**  <br>
https://github.com/Wenzel/libmicrovmi
