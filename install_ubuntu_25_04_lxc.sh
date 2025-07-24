#!/bin/bash

set -e

# Function to list available network bridges on Proxmox host
list_bridges() {
  echo "Available network bridges:"
  ip link show | grep -E '^[0-9]+: (vmbr[0-9]+):' | awk -F': ' '{print $2}'
}

# Function to prompt for integer input with validation
prompt_int() {
  local prompt_msg="$1"
  local input
  while true; do
    read -rp "$prompt_msg" input
    if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -gt 0 ]; then
      echo "$input"
      return
    else
      echo "Please enter a valid positive integer."
    fi
  done
}

# Function to prompt for yes/no input
prompt_yes_no() {
  local prompt_msg="$1"
  local input
  while true; do
    read -rp "$prompt_msg (y/n): " input
    case "$input" in
      [Yy]*) echo "yes"; return ;;
      [Nn]*) echo "no"; return ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

# Function to prompt for IP address (IPv4 or IPv6) with basic validation
prompt_ip() {
  local prompt_msg="$1"
  local ip
  while true; do
    read -rp "$prompt_msg" ip
    if [[ -z "$ip" ]]; then
      echo ""
      return
    fi
    # Basic IPv4 validation
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      echo "$ip"
      return
    fi
    # Basic IPv6 validation (simple)
    if [[ "$ip" =~ ^([0-9a-fA-F:]+)$ ]]; then
      echo "$ip"
      return
    fi
    echo "Invalid IP address format. Please try again or leave blank to skip."
  done
}

# Prompt user for container configuration
echo "=== Ubuntu 25.04 LXC Container Setup ==="

read_with_default() {
  local prompt_msg="$1"
  local default_value="$2"
  local input
  while true; do
    read -rp "$prompt_msg [$default_value]: " input
    if [ -z "$input" ]; then
      echo "$default_value"
      return
    fi
    if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -gt 0 ]; then
      echo "$input"
      return
    else
      echo "Please enter a valid positive integer."
    fi
  done
}

cpu_cores=$(read_with_default "Enter number of CPU cores for the container" 2)
memory_mb=$(read_with_default "Enter memory size in MB for the container" 4096)
disk_gb=$(read_with_default "Enter disk size in GB for the container" 60)

# Detect default storage pool (prefer ZFS if available)
default_storage_pool=$(pvesm status | awk 'NR>1 {print $1, $2}' | grep zfs | head -n1 | awk '{print $1}')
if [ -z "$default_storage_pool" ]; then
  default_storage_pool=$(pvesm status | awk 'NR>1 {print $1}' | head -n1)
fi

echo "Available storage pools:"
pvesm status | awk 'NR>1 {print $1}'

read_with_default() {
  local prompt_msg="$1"
  local default_value="$2"
  local input
  while true; do
    read -rp "$prompt_msg [$default_value]: " input
    if [ -z "$input" ]; then
      echo "$default_value"
      return
    fi
    echo "$input"
    return
  done
}

storage_pool=$(read_with_default "Enter storage pool to use for container rootfs" "$default_storage_pool")

echo
list_bridges
echo
read -rp "Enter network bridge to use from the above list: " net_bridge

ip_mode="static"
echo "Default network mode is static IP."
read -rp "Use static IP or DHCP? (static/dhcp) [static]: " ip_mode_input
if [[ "$ip_mode_input" == "dhcp" ]]; then
  ip_mode="dhcp"
fi

static_ipv4=""
gateway_ipv4=""
dns_ipv4=""
static_ipv6=""
gateway_ipv6=""
dns_ipv6=""

if [[ "$ip_mode" == "static" ]]; then
  echo "Enter static IPv4 address with subnet (e.g. 172.16.0.10/24):"
  read -rp "IPv4: " static_ipv4

  echo "Enter IPv4 gateway (e.g. 172.16.0.1):"
  read -rp "Gateway IPv4: " gateway_ipv4

  echo "Enter IPv4 DNS server (e.g. 8.8.8.8):"
  read -rp "DNS IPv4: " dns_ipv4

  ipv6_enable=""
  while true; do
    ipv6_enable=$(prompt_yes_no "Enable IPv6? (default no)")
    if [[ "$ipv6_enable" == "yes" || "$ipv6_enable" == "no" ]]; then
      break
    else
      echo "Please answer y or n."
    fi
  done

  if [[ "$ipv6_enable" == "yes" ]]; then
    echo "Enter static IPv6 address with subnet (leave blank to skip):"
    static_ipv6=$(read_with_default "IPv6" "")
    echo "Enter IPv6 gateway (leave blank to skip):"
    gateway_ipv6=$(read_with_default "Gateway IPv6" "")
    echo "Enter IPv6 DNS server (leave blank to skip):"
    dns_ipv6=$(read_with_default "DNS IPv6" "")
  else
    static_ipv6=""
    gateway_ipv6=""
    dns_ipv6=""
  fi
fi

if [ -z "$ipv6_enable" ]; then ipv6_enable="no"; fi

if [[ "$ipv6_enable" == "no" ]]; then
  static_ipv6=""
  gateway_ipv6=""
  dns_ipv6=""
fi

ssh_key_enabled=$(prompt_yes_no "Enable SSH key authentication? (default no)")
if [ -z "$ssh_key_enabled" ]; then ssh_key_enabled="no"; fi

create_sudo_user="yes"
echo "Default is to create a sudo user."
read -rp "Create a sudo user? (y/n) [y]: " create_sudo_user_input
if [[ "$create_sudo_user_input" =~ ^[Nn] ]]; then
  create_sudo_user="no"
fi

sudo_username=""
sudo_password=""

if [[ "$create_sudo_user" == "yes" ]]; then
  while true; do
    read -rp "Enter sudo username: " sudo_username
    if [[ -n "$sudo_username" ]]; then
      break
    else
      echo "Username cannot be empty."
    fi
  done
  while true; do
    read -rsp "Enter password for sudo user: " sudo_password
    echo
    read -rsp "Confirm password: " password_confirm
    echo
    if [[ "$sudo_password" == "$password_confirm" && -n "$sudo_password" ]]; then
      break
    else
      echo "Passwords do not match or empty. Please try again."
    fi
  done
fi

secure_container=$(prompt_yes_no "Secure the container (disable root SSH login, configure SSH keys)? (default no)")
if [ -z "$secure_container" ]; then secure_container="no"; fi

# Prompt user for container ID and name
prompt_ctid() {
  local input
  while true; do
    read -rp "Enter container ID (numeric): " input
    if [[ "$input" =~ ^[0-9]+$ ]]; then
      if ! pct status $input &>/dev/null; then
        echo "$input"
        return
      else
        echo "Container ID $input already exists. Please choose another."
      fi
    else
      echo "Please enter a valid numeric container ID."
    fi
  done
}

prompt_hostname() {
  local input
  while true; do
    read -rp "Enter hostname for the container: " input
    # Validate hostname: letters, digits, hyphens, no leading/trailing hyphen, max 63 chars
    # Accept lowercase letters only to avoid validation issues
    if [[ "$input" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
      echo "$input"
      return
    else
      echo "Invalid hostname. Use lowercase alphanumeric characters and hyphens only, no leading or trailing hyphens, max length 63."
    fi
  done
}

ctid=$(prompt_ctid)
echo "Using container ID: $ctid"

hostname=$(prompt_hostname)
echo "Using hostname: $hostname"

# Create LXC container with Ubuntu 25.04 template
echo "Creating LXC container..."
pct create $ctid local:vztmpl/ubuntu-25.04-standard_25.04-1_amd64.tar.zst \
  --cores $cpu_cores \
  --memory $memory_mb \
  --swap 512 \
  --rootfs $storage_pool:${disk_gb}G \
  --net0 name=eth0,bridge=$net_bridge,firewall=1

# Configure network inside container
echo "Configuring network..."

# Set hostname inside container after creation
pct exec $ctid -- hostnamectl set-hostname $hostname

# Add hostname to /etc/hosts inside container
pct exec $ctid -- bash -c "echo '127.0.1.1 $hostname' >> /etc/hosts"

if [[ "$ip_mode" == "dhcp" ]]; then
  pct set $ctid -net0 ip=dhcp
else
  # Build IP config string
  ip_config="ip=$static_ipv4/24,gw=$gateway_ipv4"
  if [[ "$ipv6_enable" == "yes" && -n "$static_ipv6" ]]; then
    ip_config="$ip_config,ip6=$static_ipv6/64,gw6=$gateway_ipv6"
  fi
  pct set $ctid -net0 name=eth0,bridge=$net_bridge,firewall=1,$ip_config
fi

# Start container
echo "Starting container..."
pct start $ctid

# Wait for container to be up
echo "Waiting for container to start..."
sleep 10

# Function to run commands inside container
pct_exec() {
  pct exec $ctid -- bash -c "$1"
}

# Update and upgrade inside container
echo "Updating container packages..."
pct_exec "apt-get update && apt-get upgrade -y"

# Install sudo and SSH
echo "Installing sudo and SSH..."
pct_exec "apt-get install -y sudo openssh-server"

# Create sudo user if requested
if [[ "$create_sudo_user" == "yes" ]]; then
  echo "Creating sudo user $sudo_username..."
  pct_exec "useradd -m -s /bin/bash $sudo_username"
  pct_exec "echo '$sudo_username:$sudo_password' | chpasswd"
  pct_exec "usermod -aG sudo $sudo_username"
fi

# Configure SSH key authentication if enabled
if [[ "$ssh_key_enabled" == "yes" ]]; then
  echo "Configuring SSH key authentication..."
  # This assumes user will manually add their public key later or you can extend script to accept key input
  pct_exec "sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config"
  pct_exec "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
else
  pct_exec "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"
fi

# Secure container SSH if requested
if [[ "$secure_container" == "yes" ]]; then
  echo "Securing SSH configuration..."
  # Disable root login
  pct_exec "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config"
fi

# Restart SSH service
pct_exec "systemctl restart sshd"

# Install Fail2Ban and UFW
echo "Installing Fail2Ban and UFW..."
pct_exec "apt-get install -y fail2ban ufw"

# Configure UFW defaults
pct_exec "ufw default deny incoming"
pct_exec "ufw default allow outgoing"
pct_exec "ufw allow ssh"
pct_exec "ufw allow http"
pct_exec "ufw allow https"
pct_exec "ufw --force enable"

# Configure Fail2Ban for SSH and NGINX
pct_exec "cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
EOF"

pct_exec "systemctl restart fail2ban"

# Install latest NGINX with Brotli and HTTP/3 support
echo "Installing latest NGINX with Brotli and HTTP/3 support..."
pct_exec "apt-get install -y curl gnupg2 ca-certificates lsb-release software-properties-common"

# Add official NGINX mainline repo for latest version
pct_exec "curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -"
pct_exec "echo 'deb https://nginx.org/packages/mainline/ubuntu/ $(lsb_release -cs) nginx' > /etc/apt/sources.list.d/nginx.list"
pct_exec "apt-get update"
pct_exec "apt-get install -y nginx"

# Install Brotli module dependencies and enable
pct_exec "apt-get install -y brotli libnginx-mod-brotli"
pct_exec "echo 'load_module modules/ngx_http_brotli_filter_module.so;' > /etc/nginx/modules-enabled/50-mod-brotli.conf"
pct_exec "echo 'load_module modules/ngx_http_brotli_static_module.so;' >> /etc/nginx/modules-enabled/50-mod-brotli.conf"

# Enable HTTP/3 support in NGINX config (example snippet)
pct_exec "sed -i '/listen 443 ssl;/a listen 443 ssl http2 reuseport; listen [::]:443 ssl http2 reuseport; listen 443 quic reuseport;' /etc/nginx/nginx.conf || true"

# Install latest PHP with FastCGI support
echo "Installing latest PHP with PHP-FPM..."
pct_exec "apt-get install -y php-fpm php-mysql php-mongodb php-pgsql php-cli php-curl php-zip php-mbstring php-bcmath php-gd"

# Install MariaDB, MongoDB, PostgreSQL
echo "Installing MariaDB, MongoDB, and PostgreSQL..."

# MariaDB
pct_exec "apt-get install -y mariadb-server"

# MongoDB - add official repo
pct_exec "curl -fsSL https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add -"
pct_exec "echo 'deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/6.0 multiverse' > /etc/apt/sources.list.d/mongodb-org-6.0.list"
pct_exec "apt-get update"
pct_exec "apt-get install -y mongodb-org"

# PostgreSQL - add official repo
pct_exec "sh -c 'echo \"deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main\" > /etc/apt/sources.list.d/pgdg.list'"
pct_exec "wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -"
pct_exec "apt-get update"
pct_exec "apt-get install -y postgresql postgresql-contrib"

# Secure MariaDB installation (basic)
pct_exec "mysql -e \"ALTER USER 'root'@'localhost' IDENTIFIED BY 'rootpassword';\" || true"
pct_exec "mysql -e \"DELETE FROM mysql.user WHERE User='';\" || true"
pct_exec "mysql -e \"DROP DATABASE IF EXISTS test;\" || true"
pct_exec "mysql -e \"FLUSH PRIVILEGES;\" || true"

# Install OpenTelemetry Collector and configure for SigNoz
echo "Installing OpenTelemetry Collector for SigNoz..."

pct_exec "curl -LO https://github.com/signoz/signoz/releases/latest/download/otelcol_linux_amd64.tar.gz"
pct_exec "tar -xzf otelcol_linux_amd64.tar.gz -C /usr/local/bin"
pct_exec "rm otelcol_linux_amd64.tar.gz"
pct_exec "chmod +x /usr/local/bin/otelcol"

# Create OpenTelemetry config file
pct_exec "cat > /etc/otel-collector-config.yaml <<EOF
receivers:
  otlp:
    protocols:
      grpc:
      http:

exporters:
  signoz:
    endpoint: \"http://localhost:3301\" # Adjust if SigNoz collector is remote
    insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [signoz]
EOF"

# Create systemd service for OpenTelemetry Collector
pct_exec "cat > /etc/systemd/system/otel-collector.service <<EOF
[Unit]
Description=OpenTelemetry Collector
After=network.target

[Service]
ExecStart=/usr/local/bin/otelcol --config /etc/otel-collector-config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOF"

pct_exec "systemctl daemon-reload"
pct_exec "systemctl enable otel-collector"
pct_exec "systemctl start otel-collector"

# Configure NGINX, PHP-FPM, and databases to export OpenTelemetry traces/logs
# (This part requires additional configuration and instrumentation; here we add placeholders)

echo "Configuring OpenTelemetry instrumentation placeholders..."

pct_exec "echo 'export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317' >> /etc/profile.d/otel.sh"
pct_exec "echo 'export OTEL_RESOURCE_ATTRIBUTES=service.name=ubuntu-lxc-container' >> /etc/profile.d/otel.sh"
pct_exec "chmod +x /etc/profile.d/otel.sh"

# Reload environment variables
pct_exec "source /etc/profile.d/otel.sh"

echo "Installation and configuration complete."
echo "Container ID: $ctid"
echo "You can enter the container with: pct enter $ctid"
