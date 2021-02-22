#!/bin/bash

DATE=`git log -1 --format=%cd --date=format:%Y%m%d.%H%M%S`
DISTRO=`lsb_release -c -s`

# Create the new directory
sshpass -e ssh gitlab-runner@build.ais -C "mkdir -p /var/www/build.ais/introvirt/$DISTRO/development/"

#Copy the files over
sshpass -e scp ./build/*.deb gitlab-runner@build.ais:/var/www/build.ais/introvirt/$DISTRO/development/

# Update the repository
sshpass -e ssh gitlab-runner@build.ais -C "/usr/local/bin/mutex sudo -H /usr/bin/freight-add -c /etc/freight.build.ais.conf /var/www/build.ais/introvirt/$DISTRO/development/*$DATE*.deb apt/$DISTRO"
