#!/bin/bash

. ./scripts/build_deps.sh

DATE=`git log -1 --format=%cd --date=format:%Y%m%d.%H%M%S`

cd build
cmake -DCMAKE_BUILD_TYPE=Release -DDOXYGEN=1 -DPACKAGE_PATCH_VERSION_EXTRA=$DATE ..
make -j4 package

