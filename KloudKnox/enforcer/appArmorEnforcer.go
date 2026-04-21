// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

const (
	// AppArmor constants
	appArmorDir     = "/etc/apparmor.d"
	kloudknoxPrefix = "kloudknox-"
	profilePerm     = 0600

	// Profile template constants
	headerTemplate = "## == Managed by KloudKnox == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile %s flags=(attach_disconnected,mediate_deleted) {\n" +
		"  ## == PRE START == ##\n" +
		"  #include <abstractions/base>\n" +
		"  file,\n" +
		"  network,\n" +
		"  capability,\n" +
		"  unix,\n" +
		"  signal,\n" +
		"  ptrace,\n" +
		"  ## == PRE END == ##\n" +
		"\n" +
		"  ## == POLICY START == ##\n"

	footerTemplate = "  ## == POLICY END == ##\n" +
		"\n" +
		"  ## == POST START == ##\n" +
		"  /lib/{*,**} rix,\n" +
		"  /lib64/{*,**} rix,\n" +
		"  /usr/lib/{*,**} rix,\n" +
		"  /usr/local/lib/{*,**} rix,\n" +
		"\n" +
		"  deny mount,\n" +
		"  deny umount,\n" +
		"  deny network packet,\n" +
		"\n" +
		"  deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,\n" +
		"  deny @{PROC}/sysrq-trigger rwklx,\n" +
		"  deny @{PROC}/mem rwklx,\n" +
		"  deny @{PROC}/kmem rwklx,\n" +
		"  deny @{PROC}/kcore rwklx,\n" +
		"\n" +
		"  deny /sys/[^f]*/** wklx,\n" +
		"  deny /sys/f[^s]*/** wklx,\n" +
		"  deny /sys/fs/[^c]*/** wklx,\n" +
		"  deny /sys/fs/c[^g]*/** wklx,\n" +
		"  deny /sys/fs/cg[^r]*/** wklx,\n" +
		"  deny /sys/firmware/** rwklx,\n" +
		"  deny /sys/kernel/security/** rwklx,\n" +
		"  ## == POST END == ##\n" +
		"}\n"
)

// AppArmorEnforcer manages AppArmor profiles at the system level
type AppArmorEnforcer struct {
	Profiles       map[string][]string
	ProfileLock    sync.RWMutex
	ProfileOpLocks sync.Map // map[string]*sync.Mutex

	// EntrypointCache maps profileName → container entrypoint paths. Reused
	// when TaskDelete has evicted the container, so a crash-looping pod can
	// still receive a profile that allows its entrypoint to re-exec.
	EntrypointCache map[string][]string
	EntrypointLock  sync.RWMutex
}

// NewAppArmorEnforcer creates and initializes a new AppArmor enforcer
func NewAppArmorEnforcer() *AppArmorEnforcer {
	ae := &AppArmorEnforcer{
		Profiles:        make(map[string][]string),
		EntrypointCache: make(map[string][]string),
	}

	// Check if AppArmor is available by verifying /etc/apparmor.d directory
	if _, err := os.Stat(appArmorDir); err != nil {
		log.Errf("AppArmor is not available: %v", err)
		return nil
	}

	// Reset any existing KloudKnox-managed profiles
	if err := ae.resetExistingProfiles(); err != nil {
		log.Errf("Failed to reset existing AppArmor profiles: %v", err)
		return nil
	}

	// Remove any unused profiles to maintain system cleanliness
	if err := ae.cleanupUnusedProfiles(); err != nil {
		log.Errf("Failed to clean up unused AppArmor profiles: %v", err)
		return nil
	}

	log.Print("Started AppArmor Enforcer")
	return ae
}

// generateProfileContent creates a complete AppArmor profile content
func (ae *AppArmorEnforcer) generateProfileContent(profileName string) string {
	return fmt.Sprintf(headerTemplate, profileName) + footerTemplate
}

// writeAndLoadProfile writes a profile to disk and loads it with apparmor_parser
func (ae *AppArmorEnforcer) writeAndLoadProfile(profileName, content string) error {
	profilePath := filepath.Join(appArmorDir, profileName)

	// Write profile file with proper permissions
	if err := os.WriteFile(profilePath, []byte(content), profilePerm); err != nil {
		return fmt.Errorf("failed to write profile file %s: %w", profileName, err)
	}

	// Load the profile using apparmor_parser
	if err := lib.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", profilePath}); err != nil {
		return fmt.Errorf("failed to load profile %s: %w", profileName, err)
	}

	return nil
}

// resetExistingProfiles resets the profiles managed by KloudKnox
func (ae *AppArmorEnforcer) resetExistingProfiles() error {
	files, err := os.ReadDir(appArmorDir)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", appArmorDir, err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), kloudknoxPrefix) {
			continue
		}

		profileContent := ae.generateProfileContent(file.Name())

		if err := ae.writeAndLoadProfile(file.Name(), profileContent); err != nil {
			return err
		}

		log.Debugf("Reset KloudKnox-managed profile: %s", file.Name())
	}

	return nil
}

// parseAAStatus parses the output of aa-status command to determine profile status
func (ae *AppArmorEnforcer) parseAAStatus(profileName string) (inEnforceMode, inUseByProcesses bool, err error) {
	output, err := lib.GetCommandOutputWithErr("aa-status", []string{})
	if err != nil {
		return false, false, fmt.Errorf("failed to check status of profile %s: %w", profileName, err)
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	var currentSection string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track which section of the output we're processing
		switch {
		case strings.Contains(line, "profiles are in enforce mode"):
			currentSection = "enforce"
		case strings.Contains(line, "processes are in enforce mode"):
			currentSection = "processes"
		case line == "":
			continue
		case currentSection == "enforce" && strings.Contains(line, profileName):
			inEnforceMode = true
		case currentSection == "processes" && strings.Contains(line, profileName):
			inUseByProcesses = true
		}
	}

	return inEnforceMode, inUseByProcesses, nil
}

// cleanupUnusedProfiles removes AppArmor profiles that are no longer in use
func (ae *AppArmorEnforcer) cleanupUnusedProfiles() error {
	files, err := os.ReadDir(appArmorDir)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", appArmorDir, err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), kloudknoxPrefix) {
			continue
		}

		inEnforceMode, inUseByProcesses, err := ae.parseAAStatus(file.Name())
		if err != nil {
			log.Errf("Failed to check status of profile %s: %v", file.Name(), err)
			continue
		}

		// Handle profiles that are in enforce mode but not in use
		if inEnforceMode && !inUseByProcesses {
			profilePath := filepath.Join(appArmorDir, file.Name())
			if err := lib.RunCommandAndWaitWithErr("apparmor_parser", []string{"-R", profilePath}); err != nil {
				log.Errf("Failed to unregister profile %s: %v", file.Name(), err)
				continue
			}
			inEnforceMode = false
		}

		// Remove completely unused profiles
		if !inEnforceMode && !inUseByProcesses {
			profilePath := filepath.Join(appArmorDir, file.Name())
			if err := os.Remove(profilePath); err != nil {
				log.Errf("Failed to remove unused profile %s: %v", file.Name(), err)
				continue
			}

			ae.ProfileLock.Lock()
			delete(ae.Profiles, file.Name())
			ae.ProfileLock.Unlock()

			log.Printf("Removed unused profile: %s", file.Name())
		}
	}

	return nil
}

// StopAppArmorEnforcer cleans up AppArmor profiles
func (ae *AppArmorEnforcer) StopAppArmorEnforcer() error {
	if ae == nil {
		return nil
	}

	ae.ProfileLock.RLock()
	profiles := make([]string, 0, len(ae.Profiles))
	for profileName := range ae.Profiles {
		profiles = append(profiles, profileName)
	}
	ae.ProfileLock.RUnlock()

	for _, profileName := range profiles {
		profileContent := ae.generateProfileContent(profileName)

		if err := ae.writeAndLoadProfile(profileName, profileContent); err != nil {
			log.Errf("Failed to apply default profile %s: %v", profileName, err)
			continue
		}

		log.Printf("Applied default profile for %s", profileName)
	}

	log.Print("Stopped AppArmor Enforcer")
	return nil
}

// isKloudKnoxProfile checks if a profile is managed by KloudKnox
func isKloudKnoxProfile(profileName string) bool {
	return strings.HasPrefix(profileName, kloudknoxPrefix)
}

// RegisterAppArmorProfile registers an AppArmor profile for a pod
func (e *RuntimeEnforcer) RegisterAppArmorProfile(profileName string) error {
	if e == nil || e.AppArmorEnforcer == nil {
		return nil
	}

	if !isKloudKnoxProfile(profileName) {
		log.Printf("AppArmor profile %s is not a KloudKnox-managed profile", profileName)
		return nil
	}

	// Use per-profile lock to serialize registration
	val, _ := e.AppArmorEnforcer.ProfileOpLocks.LoadOrStore(profileName, &sync.Mutex{})
	profileOpLock := val.(*sync.Mutex)
	profileOpLock.Lock()
	defer profileOpLock.Unlock()

	e.AppArmorEnforcer.ProfileLock.RLock()
	_, exists := e.AppArmorEnforcer.Profiles[profileName]
	e.AppArmorEnforcer.ProfileLock.RUnlock()

	if exists {
		return nil
	}

	profileContent := e.AppArmorEnforcer.generateProfileContent(profileName)

	if err := e.AppArmorEnforcer.writeAndLoadProfile(profileName, profileContent); err != nil {
		return err
	}

	e.AppArmorEnforcer.ProfileLock.Lock()
	e.AppArmorEnforcer.Profiles[profileName] = strings.Split(profileContent, "\n")
	e.AppArmorEnforcer.ProfileLock.Unlock()

	log.Printf("Registered AppArmor profile: %s", profileName)
	return nil
}

// UnregisterAppArmorProfile unregisters an AppArmor profile for a pod
func (e *RuntimeEnforcer) UnregisterAppArmorProfile(profileName string) error {
	if e == nil || e.AppArmorEnforcer == nil {
		return nil
	}

	if !isKloudKnoxProfile(profileName) {
		log.Printf("AppArmor profile %s is not a KloudKnox-managed profile", profileName)
		return nil
	}

	// Use per-profile lock to serialize unregistration
	val, _ := e.AppArmorEnforcer.ProfileOpLocks.LoadOrStore(profileName, &sync.Mutex{})
	profileOpLock := val.(*sync.Mutex)
	profileOpLock.Lock()
	defer profileOpLock.Unlock()

	e.AppArmorEnforcer.ProfileLock.RLock()
	_, exists := e.AppArmorEnforcer.Profiles[profileName]
	e.AppArmorEnforcer.ProfileLock.RUnlock()

	if !exists {
		log.Printf("AppArmor profile %s is not registered", profileName)
		return nil
	}

	profilePath := filepath.Join(appArmorDir, profileName)
	profileContent := e.AppArmorEnforcer.generateProfileContent(profileName)

	// Write default profile content with proper permissions
	if err := os.WriteFile(profilePath, []byte(profileContent), profilePerm); err != nil {
		return fmt.Errorf("failed to write profile file: %w", err)
	}

	// Check if profile is still loaded in the kernel using aa-status
	output, err := lib.GetCommandOutputWithErr("aa-status", []string{})
	if err != nil {
		return fmt.Errorf("failed to check profile status: %w", err)
	}

	if !strings.Contains(string(output), profileName) {
		// Profile is not loaded in the kernel; nothing to unload, just clean up memory
		e.AppArmorEnforcer.ProfileLock.Lock()
		delete(e.AppArmorEnforcer.Profiles, profileName)
		e.AppArmorEnforcer.ProfileLock.Unlock()

		log.Printf("Unregistered AppArmor profile (was not loaded): %s", profileName)
		return nil
	}

	// Profile IS loaded in kernel — unload it with apparmor_parser -R
	if err := lib.RunCommandAndWaitWithErr("apparmor_parser", []string{"-R", profilePath}); err != nil {
		log.Warnf("failed to unload profile %s: %v", profileName, err)
	}

	// Remove the profile file
	if err := os.Remove(profilePath); err != nil {
		return fmt.Errorf("failed to remove profile file: %w", err)
	}

	e.AppArmorEnforcer.ProfileLock.Lock()
	delete(e.AppArmorEnforcer.Profiles, profileName)
	e.AppArmorEnforcer.ProfileLock.Unlock()

	log.Printf("Unregistered AppArmor profile: %s", profileName)
	return nil
}

// appArmorAnnotationPrefix is the legacy K8s annotation that maps a container
// name to its AppArmor profile. Used to resolve profile → container(s) so we
// can look up the entrypoint binary of that specific container.
const appArmorAnnotationPrefix = "container.apparmor.security.beta.kubernetes.io/"

// containerIDsForProfile returns the container IDs of a pod whose AppArmor
// profile annotation matches the given profile name. Falls back to the pod's
// single container when no annotation mapping is available (Docker path, where
// the relation is 1:1 and pod.Annotations is empty).
func containerIDsForProfile(pod tp.Pod, profileName string) []string {
	var ids []string
	for k, v := range pod.Annotations {
		if !strings.HasPrefix(k, appArmorAnnotationPrefix) {
			continue
		}
		cname := strings.TrimPrefix(k, appArmorAnnotationPrefix)
		profile := strings.TrimPrefix(v, "localhost/")
		if profile != profileName {
			continue
		}
		for cid, n := range pod.Containers {
			if n == cname {
				ids = append(ids, cid)
			}
		}
	}
	if len(ids) == 0 && len(pod.Containers) == 1 && len(pod.AppArmorProfiles) == 1 {
		for cid := range pod.Containers {
			ids = append(ids, cid)
		}
	}
	return ids
}

// collectEntrypoints returns the binary path(s) for the container(s) mapped
// to profileName. Reads /proc/<rootPID>/exe while live and caches the result,
// so the crash-window after TaskDelete (containerID already evicted from
// GlobalData.Containers) still returns a usable entrypoint.
func (e *RuntimeEnforcer) collectEntrypoints(pod tp.Pod, profileName string) []string {
	ids := containerIDsForProfile(pod, profileName)

	fresh := make([]string, 0, len(ids))
	for _, cid := range ids {
		e.GlobalData.ContainersLock.RLock()
		c, exists := e.GlobalData.Containers[cid]
		e.GlobalData.ContainersLock.RUnlock()
		if !exists || c.RootPID == 0 {
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", c.RootPID))
		if err != nil || exe == "" {
			continue
		}
		fresh = append(fresh, exe)
	}

	if len(fresh) > 0 {
		e.AppArmorEnforcer.EntrypointLock.Lock()
		e.AppArmorEnforcer.EntrypointCache[profileName] = fresh
		e.AppArmorEnforcer.EntrypointLock.Unlock()
		return fresh
	}

	e.AppArmorEnforcer.EntrypointLock.RLock()
	cached := e.AppArmorEnforcer.EntrypointCache[profileName]
	e.AppArmorEnforcer.EntrypointLock.RUnlock()
	return cached
}

// UpdateAppArmorProfiles applies security policies to apparmor profiles of a pod.
//
// Iterates over pod.AppArmorProfiles (not pod.Containers) so crash-evicted
// containers still get their profile rewritten — otherwise the on-disk profile
// stays frozen and the kernel enforces a stale policy on the next spawn.
//
// Ordering contract: GlobalData.Pods[key].FileRules must be published BEFORE
// apparmor_parser -r runs, or the first deny event after apply can reach the
// handler before the matcher cache refreshes — findMatchedRules then silently
// drops the EACCES, losing it from alerts.jsonl.
func (e *RuntimeEnforcer) UpdateAppArmorProfiles(pod tp.Pod) error {
	if e == nil || e.AppArmorEnforcer == nil {
		return nil
	}

	for profileName, managed := range pod.AppArmorProfiles {
		if !managed {
			continue
		}
		if !isKloudKnoxProfile(profileName) {
			continue
		}

		// Check if profile is registered, if not try to register it
		e.AppArmorEnforcer.ProfileLock.RLock()
		_, pExists := e.AppArmorEnforcer.Profiles[profileName]
		e.AppArmorEnforcer.ProfileLock.RUnlock()

		if !pExists {
			if err := e.RegisterAppArmorProfile(profileName); err != nil {
				log.Warnf("Failed to register profile on the fly: %v", err)
				continue
			}
		}

		entrypoints := e.collectEntrypoints(pod, profileName)

		// Generate new profile content
		newProfile, err := e.AppArmorEnforcer.GenerateAppArmorProfile(profileName, pod.FileRules, pod.CapabilityRules, pod.IPCRules, entrypoints)
		if err != nil {
			return fmt.Errorf("failed to generate profile: %w", err)
		}

		// If the profile is empty, skip it (means no change)
		if newProfile == "" {
			continue
		}

		// Acquire per-profile lock to handle slow I/O and command execution
		val, _ := e.AppArmorEnforcer.ProfileOpLocks.LoadOrStore(profileName, &sync.Mutex{})
		profileOpLock := val.(*sync.Mutex)
		profileOpLock.Lock()

		// Get original profile for potential rollback
		e.AppArmorEnforcer.ProfileLock.RLock()
		originalProfile := e.AppArmorEnforcer.Profiles[profileName]
		e.AppArmorEnforcer.ProfileLock.RUnlock()

		// Write the new profile
		profilePath := filepath.Join(appArmorDir, profileName)
		if err := os.WriteFile(profilePath, []byte(newProfile), profilePerm); err != nil {
			profileOpLock.Unlock()
			return fmt.Errorf("failed to write profile file: %w", err)
		}

		// Publish pod.FileRules to the matcher cache FIRST, then reload the
		// kernel profile. Holding PodsLock across apparmor_parser -r would
		// stall every event-handler goroutine for the duration of the kernel
		// reload, so the commit is a short critical section taken before the
		// parser runs. The caller may have already committed these rules; the
		// re-publish here is the load-bearing step that guarantees ordering
		// relative to the subsequent kernel reload regardless of who wrote
		// first.
		podKey := pod.NamespaceName + "/" + pod.PodName
		e.GlobalData.PodsLock.Lock()
		if current, ok := e.GlobalData.Pods[podKey]; ok {
			current.FileRules = pod.FileRules
			current.CapabilityRules = pod.CapabilityRules
			current.IPCRules = pod.IPCRules
			e.GlobalData.Pods[podKey] = current
		}
		e.GlobalData.PodsLock.Unlock()

		// Apply the new profile using apparmor-parser
		if err := lib.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", profilePath}); err != nil {
			// Rollback to the original profile
			if len(originalProfile) > 0 {
				if rollbackErr := os.WriteFile(profilePath, []byte(strings.Join(originalProfile, "\n")), profilePerm); rollbackErr != nil {
					log.Errf("Failed to rollback profile %s: %v", profileName, rollbackErr)
				} else {
					// Try to reload the original profile
					if rollbackErr := lib.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", profilePath}); rollbackErr != nil {
						log.Errf("Failed to reload original profile %s: %v", profileName, rollbackErr)
					}
				}
			}
			profileOpLock.Unlock()
			return fmt.Errorf("failed to load profile: %w", err)
		}

		// Update the profile in memory (fast operation)
		e.AppArmorEnforcer.ProfileLock.Lock()
		e.AppArmorEnforcer.Profiles[profileName] = strings.Split(newProfile, "\n")
		e.AppArmorEnforcer.ProfileLock.Unlock()

		profileOpLock.Unlock()

		log.Printf("Updated security policies for profile: %s", profileName)
	}

	return nil
}
