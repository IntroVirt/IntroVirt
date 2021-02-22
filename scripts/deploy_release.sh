#!/bin/bash

TAG=`git describe --tags`
DISTRO=`lsb_release -c -s`

# Create the new directory
sshpass -e ssh gitlab-runner@packages.ais -C "mkdir -p /var/www/packages.ais/introvirt/$TAG/$DISTRO"

#Copy the files over
sshpass -e scp ./build/*.deb gitlab-runner@packages.ais:/var/www/packages.ais/introvirt/$TAG/$DISTRO

# Update the repository
sshpass -e ssh gitlab-runner@packages.ais -C "/usr/local/bin/mutex sudo -H /usr/bin/freight-add -c /etc/freight.packages.ais.conf /var/www/packages.ais/introvirt/$TAG/$DISTRO/*.deb apt/$DISTRO"
