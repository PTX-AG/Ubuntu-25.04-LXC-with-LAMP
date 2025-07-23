# Ubuntu 25.04 LXC Container Setup Script

This repository contains a comprehensive interactive bash script to create and configure an Ubuntu 25.04 LXC container on a Proxmox host. The script automates the installation and configuration of a modern web server stack with enhanced security and observability features.

## Features

- Interactive prompts for container resource allocation (CPU, memory, disk).
- Network configuration with support for DHCP or static IP (IPv4 and IPv6).
- Automatic listing of available Proxmox network bridges.
- Installation of latest NGINX with Brotli compression and HTTP/3 support.
- Installation of latest PHP with FastCGI (PHP-FPM).
- Installation and secure setup of MariaDB, MongoDB, and PostgreSQL databases.
- Installation and configuration of Fail2Ban and UFW firewall for security.
- Creation of a sudo user with password prompt.
- SSH hardening options including disabling root login.
- Installation and configuration of OpenTelemetry Collector for SigNoz integration.
- Modular, well-structured bash script designed for ease of use and customization.

## Disclaimer

This script is provided "as is" without any warranties or guarantees. Use it at your own risk. The author is not responsible for any data loss, system damage, or other issues that may arise from using this script. Always ensure you have proper backups and test in a safe environment before deploying to production.

## Usage

Run the script on your Proxmox host with:

```bash
bash -c "$(curl -fsSL URL)"
```

Replace `URL` with the actual URL where the script is hosted.

Follow the interactive prompts to configure your container and software stack.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contact

For questions or issues, please open an issue in this repository.
