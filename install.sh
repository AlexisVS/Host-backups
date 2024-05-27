#!/bin/bash

# Add a symbolic link for the eQual instance listener service
ln -s /root/host-backups/host-backups-listener.service /etc/systemd/system/host-backups-listener.service

# Reload daemon
systemctl daemon-reload

# Enable the listener service
systemctl enable host-backups-listener.service

# Start the listener service
systemctl start host-backups-listener.service