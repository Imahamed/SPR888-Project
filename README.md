# Applied Security Project — AD infrastructure

> **Purpose:**  
> This repository documents the end-to-end process for building a small enterprise-style lab, enumerating its attack surface, and reproducing realistic attacker techniques in a safe, controlled environment for learning and defense hardening.

> **Scope & Ethics:**  
> Everything here is for **authorized, educational lab use only**.  
> Do **not** target systems without explicit written permission.  

---

## Table of Contents

- [Overview](#overview)
- [Lab Topology](#lab-topology)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Methodology & Commands](#methodology--commands)
- [Evidence & Logging](#evidence--logging)
- [Cleanup & Reset](#cleanup--reset)
- [Docker Hub Repository](#docker-hub-repository)
- [Repository Layout](#repository-layout)
- [Safety Notes](#safety-notes)
- [References](#references)

---

## Overview

We built a mini-enterprise environment and practiced **enumeration → web exploitation → container post-exploitation → host access** in a lab.  
Milestones included:

- **Milestone 1:** Lab setup & access verification  
- **Milestone 2:** Enumeration (Nmap, Gobuster, Burp Suite, wfuzz)  
- **Milestone 3:** Initial compromise in a Dockerized web server; research on escalation paths and host access approach  

---

## Lab Topology

All nodes are on a flat lab network and, except Kali, are joined to Active Directory.

- **Windows AD** — Domain Services, users/groups, baseline GPOs, Sysmon  
- **Windows Server 1** — SMB, HTTP, WinRM, RDP  
- **Windows Server 2** — SMB, RPC, WinRM, PS Remoting  
- **Windows Workstation** — Windows 10, NTLM, file shares  
- **Linux (Docker host)** — Hosts the vulnerable web stack inside a container  
- **Kali (Attacker tools)** — Nmap, Gobuster, wfuzz, Burp Suite, local HTTP server, utilities

---

## Prerequisites

- Docker installed on your local machine or lab server
- An account on [Docker Hub](https://hub.docker.com)
- Internet connection to pull the image

---

## Quick Start

The quickest way to get started with the **`imahamed/holo-live2`** image is:

### 1. Pull the Image
```bash
docker pull imahamed/holo-live2:v1

