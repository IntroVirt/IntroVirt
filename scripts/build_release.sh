#!/bin/bash

. ./scripts/build_deps.sh

cd build
cmake -DCMAKE_BUILD_TYPE=Release -DDOXYGEN=1 ..
make -j4 package

