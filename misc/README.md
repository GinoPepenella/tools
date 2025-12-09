# Miscellaneous Tools

Utilities that don't fit into other categories.

## Scripts

### rickroll.sh

A harmless prank script that uses systemd user timers to periodically open a YouTube video.

**What it does:**
- Creates systemd user service and timer
- Opens Rick Astley video every 15 minutes
- Hides itself after starting
- Can be stopped and removed completely

**Requirements:**
- Linux with systemd
- xdg-open (standard on most desktop Linux)
- User account (no root needed)

**Usage:**

Start the prank:
```bash
./rickroll.sh --start
```

Stop and remove:
```bash
./.rickroll.sh --stop
```

**How it works:**
1. Creates `~/.config/systemd/user/rickroll.service`
2. Creates `~/.config/systemd/user/rickroll.timer`
3. Timer triggers every 15 minutes
4. Service opens YouTube link in default browser
5. Script renames itself to `.rickroll.sh` to hide

**Detection:**
```bash
# Check if timer is active
systemctl --user list-timers

# Check status
systemctl --user status rickroll.timer
```

**Removal:**
```bash
# If you can't find the script
systemctl --user stop rickroll.timer
systemctl --user disable rickroll.timer
rm ~/.config/systemd/user/rickroll.{service,timer}
systemctl --user daemon-reload
```

---

## Ethical Use

This prank script is intended for harmless fun between consenting parties. Use responsibly:

- Only use on systems you own or have explicit permission to modify
- Inform the recipient after a reasonable time
- Do not use in professional/production environments
- Respect others' time and property

## Disclaimer

These utilities are provided as-is for educational and entertainment purposes. The author is not responsible for misuse or any consequences resulting from the use of these tools.
