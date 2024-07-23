# C++ SDK for Verdict-as-a-Service

> [!CAUTION]
> This is a beta version. Please do not use the SDK in a production system yet.

## Running the example

Prerequisites:

* CMake

Install [vcpkg](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started?pivots=shell-bash):

```bash
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg && ./bootstrap-vcpkg.sh
export VCPKG_ROOT=/path/to/vcpkg
export PATH=$VCPKG_ROOT:$PATH
```

Build:

```bash
cmake --preset release
cmake --build build
```

Run:

```
CLIENT_ID=<your client ID> CLIENT_SECRET=<your client secret> build/vaas_example build/vaas_example
```
