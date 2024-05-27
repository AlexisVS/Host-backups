# Host backup

## Purpose

The repository is a PHP web server for handling backups of B2 private cloud instances.

It is designed to be used in conjunction with the [B2 repository](https://github.com/yesbabylon/b2) for initializing
instances using the eQual framework.

## Features

- **Backup**: The repository provides a PHP web server for handling backups of B2 private cloud instances.
- **Automation**: The server automatically handles the backup process, ensuring that your data is secure and accessible.
- **Security**: The server is designed to be secure, with encryption and authentication mechanisms in place to protect
  your data.
- **Monitoring**: The server provides monitoring tools to track the status of backups and ensure that they are running
  smoothly.

## Important Note

This repository should be placed in the ``/root`` folder of your server.

## Installation

To install the host backup server, follow these steps:

1. Clone the repository in ``/root`` of your server.
2. execute the `install.sh` script to set up the server and the ``host-backup`` service.

## Usage

The host backup server uses a ``listener.php`` script to handle the backup process.
The script listens for incoming requests from the B2 private cloud instances and initiates the backup process.

To use the host backup server call it from the B2 private cloud instance using the following command:

```bash
curl -X POST https://<host-backup-server-ip>:8000/<your-desired-route>
```

## Routes explanation

The host backup server provides the following routes:

### ``/token``

In progress

### ``/token-release``

In progress