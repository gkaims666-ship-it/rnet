# RNET Relay Server — Deployment Guide

The RNET relay is a minimal UDP forwarder. It routes encrypted frames between
clients based solely on the 4-byte session ID in the RNET frame header. It
cannot read, decrypt, or inspect any payload content.

## Requirements

- Any Linux VPS with a public IP (1 vCPU, 256 MB RAM is sufficient)
- Docker + Docker Compose v2 installed
- UDP port 7777 open in your firewall / security group

## One-command deployment

```bash
git clone https://github.com/gkaims666-ship-it/rnet.git
cd rnet/deploy
docker compose up -d
```

The relay starts immediately and listens on UDP port 7777.

## Custom port

```bash
RELAY_PORT=9000 docker compose up -d
```

## Configure the app

After the relay is running:

**Android**  
First launch → enter your server's IP or domain and port → Save.  
Or change it later in the app's Settings screen.

**iOS**  
First launch → Server Setup sheet → enter host and port → Save and continue.

## Firewall example (ufw)

```bash
ufw allow 7777/udp
ufw reload
```

## Logs

```bash
docker compose logs -f relay
```

## Update

```bash
git pull
docker compose build relay
docker compose up -d
```

## Stopping

```bash
docker compose down
```
