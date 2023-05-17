#!/bin/bash
cat <<EOF > /etc/systemd/system/codax.service
[Unit]
Description= CODAX client for detecting CPU exhaustive DOS attacks 
After=network.target
StartLimitBurst=5
StartLimitIntervalSec=10

[Service]
Type=simple
User=root
ExecStart=/usr/bin/container_tracer
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable codax.service
systemctl start codax.service
