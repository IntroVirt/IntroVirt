![IntroVirt](https://github.com/IntroVirt/IntroVirt/raw/main/.github/images/logo.png)

## Description
TBD

## **Quick start**
![GitHub release (latest by date)](https://img.shields.io/github/v/release/IntroVirt/IntroVirt?color=brightgreen)

Ubuntu install from Launchpad PPA (ensure no VMs are running first):
```
sudo add-apt-repository ppa:srpape/introvirt
sudo apt-get update
sudo apt-get install kvm-introvirt introvirt-tools libintrovirt-dev
```

You will need to be booted into the correct kernel, based on the latest version of kvm-introvirt.
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

If using the launchpad PPA, libmspdb-dev can be installed:
```
sudo apt-get install cmake libcurl4-openssl-dev libboost-dev libboost-program-options-dev libboost-stacktrace-dev liblog4cxx-dev libmspdb-dev python3-jinja2 python3 doxygen clang-format
```

Otherwise, build and install libmspdb
```
sudo apt-get -y cmake libcurl4-openssl-dev libboost-dev
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

## **Testing**
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FIntroVirt%2FIntroVirt%2Fbadge&style=flat)](https://actions-badge.atrox.dev/IntroVirt/IntroVirt/goto)

IntroVirt leverages the following tools to ensure the highest possible code quality. Each pull request undergoes the following rigorous testing and review:
-   **Static Analysis:** TBD
-   **Dynamic Analysis:** TBD
-   **Code Coverage:** TBD
-   **Coding Standards**: TBD
-   **Style**: TBD
-   **Documentation**: TBD

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
