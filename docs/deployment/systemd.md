# Systemd Service Deployment

Deploy OpenLabels as a systemd service for continuous file watching and scheduled scans.

## Prerequisites

- Python 3.10+ installed
- OpenLabels installed (`pip install openlabels`)
- Root or sudo access for systemd configuration

## Service Installation

### 1. Create Service User

```bash
# Create dedicated user
sudo useradd -r -s /bin/false -d /var/lib/openlabels openlabels

# Create directories
sudo mkdir -p /var/lib/openlabels
sudo mkdir -p /var/log/openlabels
sudo mkdir -p /etc/openlabels

# Set ownership
sudo chown -R openlabels:openlabels /var/lib/openlabels
sudo chown -R openlabels:openlabels /var/log/openlabels
```

### 2. Create Configuration File

```bash
sudo tee /etc/openlabels/config.env << 'EOF'
# OpenLabels Configuration
OPENLABELS_LOG_LEVEL=INFO
OPENLABELS_LOG_FILE=/var/log/openlabels/openlabels.log
OPENLABELS_LOG_FORMAT=json
OPENLABELS_INDEX_PATH=/var/lib/openlabels/index.db
OPENLABELS_DEFAULT_EXPOSURE=INTERNAL
OPENLABELS_QUARANTINE_DIR=/var/lib/openlabels/quarantine
EOF

sudo chmod 600 /etc/openlabels/config.env
sudo chown openlabels:openlabels /etc/openlabels/config.env
```

### 3. File Watcher Service

Create `/etc/systemd/system/openlabels-watcher.service`:

```ini
[Unit]
Description=OpenLabels File Watcher
Documentation=https://github.com/chillbot-io/OpenRisk
After=network.target

[Service]
Type=simple
User=openlabels
Group=openlabels
EnvironmentFile=/etc/openlabels/config.env
ExecStart=/usr/local/bin/openlabels watch /data/sensitive --recursive
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/openlabels /var/log/openlabels
ReadOnlyPaths=/data/sensitive
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Resource limits
MemoryMax=2G
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

### 4. Scheduled Scan Service

Create `/etc/systemd/system/openlabels-scan.service`:

```ini
[Unit]
Description=OpenLabels Scheduled Scan
Documentation=https://github.com/chillbot-io/OpenRisk

[Service]
Type=oneshot
User=openlabels
Group=openlabels
EnvironmentFile=/etc/openlabels/config.env
ExecStart=/usr/local/bin/openlabels scan /data/sensitive --recursive --format json --output /var/lib/openlabels/scan-results.json

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/openlabels /var/log/openlabels
ReadOnlyPaths=/data/sensitive
PrivateTmp=yes
```

Create `/etc/systemd/system/openlabels-scan.timer`:

```ini
[Unit]
Description=Run OpenLabels scan daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
```

### 5. Enable and Start Services

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable openlabels-watcher.service
sudo systemctl enable openlabels-scan.timer

# Start services
sudo systemctl start openlabels-watcher.service
sudo systemctl start openlabels-scan.timer

# Check status
sudo systemctl status openlabels-watcher.service
sudo systemctl status openlabels-scan.timer
```

## Log Management

### Configure logrotate

Create `/etc/logrotate.d/openlabels`:

```
/var/log/openlabels/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 openlabels openlabels
    sharedscripts
    postrotate
        systemctl reload openlabels-watcher.service > /dev/null 2>&1 || true
    endscript
}
```

### View logs

```bash
# Watcher logs
sudo journalctl -u openlabels-watcher.service -f

# Scan timer logs
sudo journalctl -u openlabels-scan.service

# Application logs
sudo tail -f /var/log/openlabels/openlabels.log | jq .
```

## Health Monitoring

### Health check script

Create `/usr/local/bin/openlabels-healthcheck`:

```bash
#!/bin/bash
set -e

# Run health check
/usr/local/bin/openlabels health --json > /tmp/health.json

# Check result
if jq -e '.healthy' /tmp/health.json > /dev/null; then
    echo "OK"
    exit 0
else
    echo "UNHEALTHY"
    jq '.checks[] | select(.status != "PASS")' /tmp/health.json
    exit 1
fi
```

```bash
sudo chmod +x /usr/local/bin/openlabels-healthcheck
```

### Integrate with monitoring

Add to your monitoring system (Nagios, Prometheus, etc.):

```bash
# For Prometheus node_exporter textfile collector
/usr/local/bin/openlabels health --json | \
  jq -r '"openlabels_health_status " + (if .healthy then "1" else "0" end)' \
  > /var/lib/node_exporter/textfile_collector/openlabels.prom
```

## Troubleshooting

### Service won't start

```bash
# Check service status
sudo systemctl status openlabels-watcher.service

# Check journal for errors
sudo journalctl -u openlabels-watcher.service -n 50 --no-pager

# Verify permissions
sudo -u openlabels /usr/local/bin/openlabels health
```

### Permission denied

```bash
# Add openlabels user to required groups
sudo usermod -aG datagroup openlabels

# Or adjust file permissions
sudo setfacl -R -m u:openlabels:rx /data/sensitive
```

### High memory usage

Adjust the MemoryMax limit in the service file:

```ini
[Service]
MemoryMax=4G
```

Then reload:

```bash
sudo systemctl daemon-reload
sudo systemctl restart openlabels-watcher.service
```
