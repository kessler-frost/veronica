package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
)

const (
	vmName      = "veronica"
	serviceName = "veronica"
	daemonBin   = "/usr/local/bin/veronicad"
	daemonPkg   = "./cmd/veronicad/"
)

func init() {
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(vmCmd)

	vmCmd.AddCommand(vmStartCmd)
	vmCmd.AddCommand(vmStopCmd)
	vmCmd.AddCommand(vmSSHCmd)
}

// vmRunning returns true if the Lima VM is in running state.
func vmRunning() (bool, error) {
	out, err := exec.Command("limactl", "list", "--json").Output()
	if err != nil {
		return false, fmt.Errorf("limactl list: %w", err)
	}

	var instances []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	for _, line := range splitLines(out) {
		if len(line) == 0 {
			continue
		}
		var inst struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if json.Unmarshal(line, &inst) == nil && inst.Name == vmName {
			instances = append(instances, inst)
		}
	}

	if len(instances) == 0 {
		return false, fmt.Errorf("lima VM %q not found — create it first:\n  limactl create --name=%s lima/veronica.yaml", vmName, vmName)
	}

	return instances[0].Status == "Running", nil
}

// splitLines splits a byte slice into non-empty lines.
func splitLines(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				lines = append(lines, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}

// vmShell runs a command inside the Lima VM and streams output to stdout/stderr.
func vmShell(args ...string) error {
	cmdArgs := append([]string{"shell", vmName, "--"}, args...)
	cmd := exec.Command("limactl", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// execVMShell replaces the current process with limactl shell (for interactive use).
func execVMShell(args ...string) error {
	limactlPath, err := exec.LookPath("limactl")
	if err != nil {
		return fmt.Errorf("limactl not found in PATH: %w", err)
	}
	cmdArgs := append([]string{"limactl", "shell", vmName, "--"}, args...)
	return syscall.Exec(limactlPath, cmdArgs, os.Environ())
}

// --- start ---

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Ensure the Lima VM is running and start the Veronica systemd service",
	RunE: func(cmd *cobra.Command, args []string) error {
		running, err := vmRunning()
		if err != nil {
			return err
		}
		if !running {
			fmt.Printf("Starting Lima VM %q...\n", vmName)
			c := exec.Command("limactl", "start", vmName)
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			if err := c.Run(); err != nil {
				return fmt.Errorf("limactl start: %w", err)
			}
		} else {
			fmt.Printf("Lima VM %q is already running.\n", vmName)
		}

		fmt.Printf("Starting systemd service %q...\n", serviceName)
		return vmShell("sudo", "systemctl", "start", serviceName)
	},
}

// --- stop ---

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the Veronica systemd service",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Stopping systemd service %q...\n", serviceName)
		return vmShell("sudo", "systemctl", "stop", serviceName)
	},
}

// --- status ---

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show VM status and daemon service status",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("=== Lima VM status ===")
		c := exec.Command("limactl", "list", vmName)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		_ = c.Run() // non-zero is informational; output already streamed to stdout

		fmt.Println("\n=== Systemd service status ===")
		_ = vmShell("sudo", "systemctl", "status", serviceName) // non-zero when service is stopped is informational
		return nil
	},
}

// --- logs ---

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Stream journalctl logs for the Veronica service (Ctrl+C to stop)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return execVMShell("sudo", "journalctl", "-u", serviceName, "-f")
	},
}

// --- build ---

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build the daemon in the VM, install it, and restart the service",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Building daemon inside VM...")
		if err := vmShell("bash", "-c",
			fmt.Sprintf("cd /Users/*/dev/veronica && GOTOOLCHAIN=auto sudo -E go build -o %s %s", daemonBin, daemonPkg),
		); err != nil {
			return fmt.Errorf("build failed: %w", err)
		}

		fmt.Println("Restarting service...")
		return vmShell("sudo", "systemctl", "restart", serviceName)
	},
}

// --- run ---

var runCmd = &cobra.Command{
	Use:                "run -- [command...]",
	Short:              "Run a command inside the VM (use -- before the command)",
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Strip leading "--" if present
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			return fmt.Errorf("no command provided")
		}
		return vmShell(args...)
	},
}

// --- setup ---

const projectPath = "/Users/fimbulwinter/dev/veronica"

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Full setup: generate vmlinux.h, compile eBPF, generate Go bindings, build daemon, install systemd service",
	RunE: func(cmd *cobra.Command, args []string) error {
		running, err := vmRunning()
		if err != nil {
			return err
		}
		if !running {
			return fmt.Errorf("VM is not running — run `veronica vm start` first")
		}

		ebpfDir := projectPath + "/internal/ebpf/programs"

		fmt.Println("1/5 Generating vmlinux.h...")
		if err := vmShell("bash", "-c",
			fmt.Sprintf("cd %s && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h", ebpfDir),
		); err != nil {
			return fmt.Errorf("vmlinux.h generation failed: %w", err)
		}

		fmt.Println("2/5 Compiling eBPF programs...")
		for _, prog := range []string{"process_exec", "file_open", "net_connect", "process_exit"} {
			if err := vmShell("bash", "-c",
				fmt.Sprintf("cd %s && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c %s.c -o %s.o", ebpfDir, prog, prog),
			); err != nil {
				return fmt.Errorf("compile %s failed: %w", prog, err)
			}
			fmt.Printf("   %s.o OK\n", prog)
		}

		fmt.Println("3/5 Generating Go bindings (bpf2go)...")
		if err := vmShell("bash", "-c",
			fmt.Sprintf("cd %s && GOTOOLCHAIN=auto go generate ./internal/ebpf/bpf/", projectPath),
		); err != nil {
			return fmt.Errorf("bpf2go failed: %w", err)
		}

		fmt.Println("4/5 Building daemon...")
		if err := vmShell("bash", "-c",
			fmt.Sprintf("cd %s && GOTOOLCHAIN=auto sudo -E go build -o %s %s", projectPath, daemonBin, daemonPkg),
		); err != nil {
			return fmt.Errorf("build failed: %w", err)
		}

		fmt.Println("5/5 Installing systemd service...")
		if err := vmShell("sudo", "cp",
			projectPath+"/lima/veronica.service", "/etc/systemd/system/veronica.service",
		); err != nil {
			return fmt.Errorf("install service failed: %w", err)
		}
		if err := vmShell("sudo", "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("daemon-reload failed: %w", err)
		}
		if err := vmShell("sudo", "systemctl", "enable", serviceName); err != nil {
			return fmt.Errorf("enable service failed: %w", err)
		}

		fmt.Println("Setup complete. Run `veronica start` to start the daemon.")
		return nil
	},
}

// --- vm ---

var vmCmd = &cobra.Command{
	Use:   "vm",
	Short: "Manage the Lima VM lifecycle",
}

var vmStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Lima VM",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := exec.Command("limactl", "start", vmName)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	},
}

var vmStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the Lima VM",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := exec.Command("limactl", "stop", vmName)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	},
}

var vmSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Open an interactive shell in the Lima VM",
	RunE: func(cmd *cobra.Command, args []string) error {
		limactlPath, err := exec.LookPath("limactl")
		if err != nil {
			return fmt.Errorf("limactl not found in PATH: %w", err)
		}
		return syscall.Exec(limactlPath, []string{"limactl", "shell", vmName}, os.Environ())
	},
}
