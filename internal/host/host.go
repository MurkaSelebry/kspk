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
	// Podman specific marker files
	if _, err := os.Stat("/.containerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	// Systemd hint when running inside a container
	if b, err := os.ReadFile("/run/systemd/container"); err == nil {
		ls := strings.ToLower(string(b))
		if ls != "" && (strings.Contains(ls, "podman") || strings.Contains(ls, "docker") || strings.Contains(ls, "container")) {
			return true
		}
	}
	// cgroup markers (cgroup v1/v2)
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		ls := strings.ToLower(string(data))
		if containsAny(ls, []string{"docker", "kubepods", "containerd", "podman", "libpod", "crio", "oci"}) {
			return true
		}
	}
	// Env variable often set by runtimes
	if v := strings.ToLower(os.Getenv("container")); v != "" {
		return true
	}
	if v := strings.ToLower(os.Getenv("CONTAINER")); v != "" { // some systems use upper-case
		return true
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
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
