package host

import (
	"os"
	"strings"
)

// DetectHostType tries to determine if running in container, vm or physical.
// It returns one of: "container", "vm", "physical".
func DetectHostType() string {
	// 1) Respect explicit override via env
	if v := os.Getenv("HOST_TYPE"); v != "" {
		return strings.ToLower(v)
	}
	// 2) Heuristics for containers
	if isContainer() {
		return "container"
	}
	// 3) Heuristics for VMs (very rough)
	if isVM() {
		return "vm"
	}
	return "physical"
}

func isContainer() bool {
	// Common container clues
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		ls := strings.ToLower(string(data))
		if strings.Contains(ls, "docker") || strings.Contains(ls, "kubepods") || strings.Contains(ls, "containerd") || strings.Contains(ls, "podman") {
			return true
		}
	}
	return false
}

func isVM() bool {
	// Non-root readable product info often hints hypervisors
	paths := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			ls := strings.ToLower(string(b))
			if strings.Contains(ls, "kvm") || strings.Contains(ls, "virtualbox") || strings.Contains(ls, "vmware") || strings.Contains(ls, "hyper-v") || strings.Contains(ls, "hyperv") || strings.Contains(ls, "qemu") || strings.Contains(ls, "xen") {
				return true
			}
		}
	}
	return false
}
