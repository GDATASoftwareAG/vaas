#!/bin/bash
set -ex
cmake --preset release
cmake --build build
./build/vaas_test