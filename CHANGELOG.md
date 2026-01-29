# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* This changelog
* A contributing document
* Added debian changelog files for noble and jammy
* Added support for Ubuntu 22.04 and 24.04
* Added supported kernel chart to README.md
* Finished the `vmcall_interface` example
    * Added in-guest code for interfacing with the `vmcall_interface` example tool
* Updated supported kernel and OS chart in README

### Fixed

* Added missing `#include <cstdint>` to several source files to get build to pass on Ubuntu 24.04
* Added missing deps to the readme for building from scratch on a clean system
* Fixed CI and auto-release
* Fixed a segfault at exit when DEBUG/TRACE logging are enabled

### Removed

* Removed unfinished example from `examples`

### Changed

* Removed outdated instructions from readme
* Updated `debian/copyright`
