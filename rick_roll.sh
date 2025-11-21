#!/usr/bin/env bash

URL="https://www.youtube.com/watch?v=DLzxrzFCyOs&list=RDDLzxrzFCyOs&start_radio=1"
SERVICE_NAME="rickroll.service"
TIMER_NAME="rickroll.timer"

SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

start_prank() {
    mkdir -p "$SYSTEMD_USER_DIR"

    # Create the systemd service
    cat > "$SYSTEMD_USER_DIR/$SERVICE_NAME" <<EOF
[Unit]
Description=Rickroll every 15 minutes

[Service]
Type=oneshot
ExecStart=/usr/bin/xdg-open "$URL"
EOF

    # Create the systemd timer
    cat > "$SYSTEMD_USER_DIR/$TIMER_NAME" <<EOF
[Unit]
Description=Timer to Rickroll every 15 minutes

[Timer]
OnUnitActiveSec=15min
OnBootSec=1min
AccuracySec=1s
Unit=$SERVICE_NAME

[Install]
WantedBy=default.target
EOF

    # Reload user systemd units
    systemctl --user daemon-reload

    # Enable + start the timer
    systemctl --user enable --now "$TIMER_NAME"

    echo "Prank started. The link will open every 15 minutes."
}

stop_prank() {
    # Stop and disable the timer
    systemctl --user stop "$TIMER_NAME" 2>/dev/null
    systemctl --user disable "$TIMER_NAME" 2>/dev/null

    # Remove files
    rm -f "$SYSTEMD_USER_DIR/$SERVICE_NAME"
    rm -f "$SYSTEMD_USER_DIR/$TIMER_NAME"

    # Reload systemd
    systemctl --user daemon-reload

    echo "Prank stopped and all traces removed."
}

case "$1" in
    --start)
        start_prank
        ;;
    --stop)
        stop_prank
        ;;
    *)
        echo "Usage: $0 --start | --stop"
        exit 1
        ;;
esac

mv rick_roll.sh ./.rick_roll.sh
