#!/bin/bash

DISTRO=`lsb_release -c -s`

# Install libmspdb-dev
curl http://build.ais/pubkey.gpg | apt-key add -
echo "deb http://build.ais/ubuntu $DISTRO main" > /etc/apt/sources.list.d/build.ais.list
apt-get update
apt-get install -y libmspdb-dev

