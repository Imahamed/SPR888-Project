# Virtual Machine Setup Guide

> **Purpose:**
> This document outlines how to configure the virtualized environment for replicating the Applied Security Project lab network. It assumes VirtualBox or VMware is used, but can be adapted to any virtualization platform.

---
## Table of Contents

- [Host Machine Requirements](#host-machine-requirements)
- [Virtual Machine Overview](#virtual-machine-overview)
- [Network Configuration](#network-configuration)
- [VM Configuration Specs](#vm-configuration-specs)
- [LMAP Stack Setup on Linux](#lmap-stack-setup-on-linux)
- [Downgrade Sudo to Vulnerable Version](#downgrade-sudo-to-vulnerable-version)
- [Windows RDP Setup for Domain Controller](#windows-rdp-setup-for-domain-controller)
- [SMB Setup for Windows Server](#smb-setup-for-windows-server)
- [Firewall Rules to Block External Network Pings](#firewall-rules-to-block-external-network-pings)
- [Additional Notes](#additional-notes)
- [Kali Linux Tools (Required Only)](#kali-linux-tools-required-only)
- [Optional Enhancements](#optional-enhancements)

---
## Host Machine Requirements

The virtual lab environment is hosted on the following system:

| Component      | Specification             |
| -------------- | ------------------------- |
| CPU            | Intel Core i7-12700H      |
| RAM            | 32 GB DDR5                |
| Storage        | 1 TB NVMe SSD             |
| Platform       | VMware Workstation Pro 17 |
| Host OS        | Windows 11 Pro x64        |

---
## Virtual Machine Overview

| Role                | VM Name         | IP Address(es)                   | Notes                                 |
| ------------------- | --------------- | -------------------------------- | ------------------------------------- |
| Kali Linux          | kali-attacker   | 192.168.100.130                  | Attacker box                          |
| Docker Host (Linux) | docker-host     | 192.168.198.135, 192.168.100.131 | Dual NICs: Internal + Attacker bridge |
| Windows DC          | win-dc          | 192.168.198.140                  | Domain Controller                     |
| Windows Server 1    | win-server1     | 192.168.198.141                  | Member Server                         |
| Windows Server 2    | win-server2     | 192.168.198.142                  | Member Server                         |
| Windows Workstation | win-workstation | 192.168.198.144                  | User endpoint                         |

---

## Network Configuration

### Virtual Networks

* **Internal Lab Network:** `192.168.198.0/24`
* **Attacker Bridge Network:** `192.168.100.0/24`

Configure VM network adapters as follows:

| VM Name         | Adapter 1               | Adapter 2           |
| --------------- | ----------------------- | ------------------- |
| kali-attacker   | Bridged to host network | None                |
| docker-host     | Internal Network        | Bridged to attacker |
| win-dc          | Internal Network        | None                |
| win-server1     | Internal Network        | None                |
| win-server2     | Internal Network        | None                |
| win-workstation | Internal Network        | None                |

> **Note:** Use static IPs inside each VM to avoid DHCP inconsistency.

---

## VM Configuration Specs

Minimum resource allocations:

| Role                | CPU | RAM | Disk Size |
| ------------------- | --- | --- | --------- |
| Kali Linux          | 2   | 2GB | 20GB      |
| Docker Host (Linux) | 2   | 2GB | 15GB      |
| Windows DC          | 2   | 4GB | 40GB      |
| Windows Server 1    | 2   | 4GB | 30GB      |
| Windows Server 2    | 2   | 4GB | 30GB      |
| Windows Workstation | 2   | 4GB | 30GB      |

---

## LMAP Stack Setup on Linux

To configure the Linux machine (Docker Host) with a secure and functional LMAP (Linux, MySQL, Apache, PHP) stack:

### Step 1: Install Apache, MySQL, PHP

```bash
sudo apt update && sudo apt install apache2 mysql-server php libapache2-mod-php php-mysql -y
```

### Step 2: Enable and Start Services

```bash
sudo systemctl enable apache2
sudo systemctl start apache2
sudo systemctl enable mysql
sudo systemctl start mysql
```

### Step 3: Configure MySQL `secure_file_priv` to NULL

1. Open MySQL config file:

```bash
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
```

2. Add or modify this line under `[mysqld]` section:

```ini
secure_file_priv = NULL
```

3. Restart MySQL:

```bash
sudo systemctl restart mysql
```

### Step 4: Create MySQL Admin User

```bash
sudo mysql -u root -p
```

Then inside MySQL shell:

```sql
CREATE USER 'admin'@'localhost' IDENTIFIED BY '!123SecureAdminDashboard321!';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EXIT;
```
### step 5: Download and run the docker container (Log in to your docker account first)

```bash
docker pull imahamed/holo-live2:v1
```

#### Run the Container

```bash
docker run -it --rm -p 8080:8080 imahamed/holo-live2:v1
```

#### Verify the Container is Running

```bash
docker ps
```
### Step 6: Ensure a specific version of sudo is installed (The latest version of sudo patches this vulnerability)

## Downgrade Sudo to Vulnerable Version

### Step 1: Remove Current Sudo

```bash
sudo apt remove sudo -y
```

### Step 2: Install Build Dependencies

```bash
sudo apt install -y wget build-essential libpam0g-dev libssl-dev
```

### Step 3: Download Vulnerable Version

```bash
wget https://www.sudo.ws/dist/sudo-1.9.15p2.tar.gz
tar -xvzf sudo-1.9.15p2.tar.gz
cd sudo-1.9.15p2
```

### Step 4: Build and Install

```bash
./configure --prefix=/usr --with-pam
make
sudo make install
````
### Step 5: Verify Version

```bash
sudo --version
```
You should see:

```
Sudo version 1.9.15p2
```

---
## Setting on all Windows Machine
### Block Incoming ICMP Echo Requests from Outside the Internal Network

Open PowerShell as Administrator:

```powershell
New-NetFirewallRule -Name "Block-ICMP-External" -DisplayName "Block ICMP from Non-Domain Hosts" -Description "Block ping from any non-domain sources" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Block -RemoteAddress Any -LocalAddress Any -Enabled True -Profile Public,Private
```

## Windows RDP Setup for Domain Controller

To enable RDP access to the Domain Controller (DC) for all authenticated domain users:

### Step 1: Enable RDP

Open PowerShell as Administrator on the DC and run:

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

### Step 2: Add Domain Users to RDP Group

```powershell
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "DOMAIN\Domain Users"
```

> Replace `DOMAIN` with the actual domain name used in your setup.

### Step 3: Verify RDP Listening Status

```powershell
Get-NetTCPConnection -LocalPort 3389
```

---

## SMB Setup for Windows Server

To enable SMB (Server Message Block) on Windows Server 1 and 2 for file sharing:

### Step 1: Install SMB Feature (if not already enabled)

Open PowerShell as Administrator:

```powershell
Install-WindowsFeature FS-FileServer
```

### Step 2: Create a Shared Folder (Choose any shared folder; this is your choice :) )

```powershell
New-Item -Path "C:\SMBShare" -ItemType Directory
New-SmbShare -Name \"Share\" -Path \"C:\SMBShare\" -FullAccess \"Domain Users\"
```

### Step 3: Adjust Firewall Settings

```powershell
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
```
---


## Additional Notes

* Ensure **Guest Additions / VMware Tools** are installed on each VM.
* Snapshots are recommended after base configuration and domain join.
* Enable clipboard and shared folders on Kali for easier transfer of exploits and tools.

---

## Optional Enhancements

* Install **Sysmon** on Windows hosts for event tracing.
* Configure **WinRM** and **PowerShell Remoting** on Windows Servers.
* Pre-install  **John**, **linPEAS**, and **mimikatz** in Kali.

---

## Kali Linux Tools (Required Only)

Install only the tools that are used during the lab walkthrough:

### Required Tools

```bash
sudo apt update && sudo apt install -y john curl python3 smbclient remmina sshuttle
```

### Additional Setup

* **Python Web Server:** Used for file transfers

  ```bash
  python3 -m http.server 8000
  ```
* **Transfer Tools:** Use `curl` or `scp` as needed to fetch scripts or share outputs

---