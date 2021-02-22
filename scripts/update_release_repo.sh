#!/bin/bash

# Update the repository
sshpass -e ssh gitlab-runner@packages.ais -C "/usr/local/bin/mutex sudo -H /usr/bin/freight-cache -c /etc/freight.packages.ais.conf"
