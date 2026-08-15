package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	systemdUnit = `[Unit]
Description=Shared IP - Domain-based SNI/HTTP reverse proxy
After=network.target

[Service]
Type=simple
ExecStart=BINARY_PATH daemon
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=shared-ip

[Install]
WantedBy=multi-user.target
`

	sysvinitScript = `#!/bin/sh
### BEGIN INIT INFO
# Provides:          shared-ip
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Shared IP reverse proxy
# Description:       Domain-based SNI/HTTP reverse proxy
### END INIT INFO

NAME="shared-ip"
DAEMON="BINARY_PATH"
PIDFILE="/var/run/$NAME.pid"
LOGFILE="/var/log/$NAME.log"

case "$1" in
    start)
        echo "Starting $NAME..."
        $DAEMON daemon >> "$LOGFILE" 2>&1 &
        echo $! > "$PIDFILE"
        echo "Started with PID $(cat $PIDFILE)"
        ;;
    stop)
        if [ -f "$PIDFILE" ]; then
            echo "Stopping $NAME..."
            kill $(cat "$PIDFILE") 2>/dev/null
            rm -f "$PIDFILE"
            echo "Stopped"
        else
            echo "$NAME is not running"
        fi
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
            echo "$NAME is running (PID $(cat $PIDFILE))"
        else
            echo "$NAME is not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
exit 0
`
)

func Install(binaryPath string) error {
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}

	// Detect init system
	if isSystemd() {
		return installSystemd(absPath)
	}
	return installSysVinit(absPath)
}

func Uninstall() error {
	if isSystemd() {
		return uninstallSystemd()
	}
	return uninstallSysVinit()
}

func Start() error {
	if isSystemd() {
		return runCmd("systemctl", "start", "shared-ip")
	}
	return runCmd("service", "shared-ip", "start")
}

func Stop() error {
	if isSystemd() {
		return runCmd("systemctl", "stop", "shared-ip")
	}
	return runCmd("service", "shared-ip", "stop")
}

func Restart() error {
	if isSystemd() {
		return runCmd("systemctl", "restart", "shared-ip")
	}
	return runCmd("service", "shared-ip", "restart")
}

func Status() (string, error) {
	if isSystemd() {
		out, err := exec.Command("systemctl", "status", "shared-ip").CombinedOutput()
		return string(out), err
	}
	out, err := exec.Command("service", "shared-ip", "status").CombinedOutput()
	return string(out), err
}

func installSystemd(binaryPath string) error {
	unitPath := "/etc/systemd/system/shared-ip.service"

	content := strings.ReplaceAll(systemdUnit, "BINARY_PATH", binaryPath)

	if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return err
	}

	fmt.Println("Service installed. Use: service shared-ip start")
	return nil
}

func uninstallSystemd() error {
	// Stop and disable
	runCmd("systemctl", "stop", "shared-ip")
	runCmd("systemctl", "disable", "shared-ip")

	unitPath := "/etc/systemd/system/shared-ip.service"
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	runCmd("systemctl", "daemon-reload")
	fmt.Println("Service uninstalled")
	return nil
}

func installSysVinit(binaryPath string) error {
	scriptPath := "/etc/init.d/shared-ip"

	content := strings.ReplaceAll(sysvinitScript, "BINARY_PATH", binaryPath)

	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("write init script: %w", err)
	}

	// Try to register with update-rc.d or chkconfig
	if _, err := exec.LookPath("update-rc.d"); err == nil {
		runCmd("update-rc.d", "shared-ip", "defaults")
	} else if _, err := exec.LookPath("chkconfig"); err == nil {
		runCmd("chkconfig", "--add", "shared-ip")
	}

	fmt.Println("Service installed. Use: service shared-ip start")
	return nil
}

func uninstallSysVinit() error {
	runCmd("service", "shared-ip", "stop")

	if _, err := exec.LookPath("update-rc.d"); err == nil {
		runCmd("update-rc.d", "-f", "shared-ip", "remove")
	} else if _, err := exec.LookPath("chkconfig"); err == nil {
		runCmd("chkconfig", "--del", "shared-ip")
	}

	scriptPath := "/etc/init.d/shared-ip"
	if err := os.Remove(scriptPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove init script: %w", err)
	}

	fmt.Println("Service uninstalled")
	return nil
}

func isSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s (%w)", name, strings.Join(args, " "), string(out), err)
	}
	return nil
}
