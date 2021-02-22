#!/bin/bash

# Update the repository
sshpass -e ssh gitlab-runner@build.ais -C "/usr/local/bin/mutex sudo -H /usr/bin/freight-cache -c /etc/freight.build.ais.conf"
