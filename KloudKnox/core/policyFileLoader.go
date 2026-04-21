// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	securityv1 "github.com/boanlab/KloudKnox/operator/api/v1"
	"github.com/fsnotify/fsnotify"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// PolicyFileLoader watches a directory of KloudKnoxPolicy YAML files and
// mirrors ADD / MODIFY / DELETE into KloudKnox state, reusing the same
// conversion + pod-application code paths as the K8s CRD watcher. It is the
// primary policy delivery channel for Docker-only (standalone) operation.
type PolicyFileLoader struct {
	ctx    context.Context
	cancel context.CancelFunc
	dir    string

	watcher *fsnotify.Watcher

	// cache maps absolute file path → the list of policy names originally
	// loaded from that file. Needed so that a DELETE/rename can remove every
	// policy that the file contributed, even for multi-document YAMLs.
	mu    sync.Mutex
	cache map[string][]policyCacheEntry

	// retryAttempts counts consecutive parse failures per file. External
	// editors (vim, sed -i without atomic save) can emit WRITE events mid-edit
	// with a partial file; debounced retry lets us observe the final state.
	retryAttempts map[string]int
	retryTimers   map[string]*time.Timer
}

const (
	policyRetryDelay    = 100 * time.Millisecond
	policyMaxRetryTries = 3
)

type policyCacheEntry struct {
	namespace string
	name      string
	policy    tp.KloudKnoxPolicy
}

// NewPolicyFileLoader initialises the watcher, seeds the cache with existing
// YAML files in the configured directory, and starts the watch goroutine.
func NewPolicyFileLoader(knox *KloudKnox) (*PolicyFileLoader, error) {
	dir := cfg.GlobalCfg.PolicyDir
	if dir == "" {
		return nil, errors.New("policyDir is empty")
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to ensure policy dir %s: %w", dir, err)
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("failed to watch %s: %w", dir, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &PolicyFileLoader{
		ctx:           ctx,
		cancel:        cancel,
		dir:           dir,
		watcher:       w,
		cache:         make(map[string][]policyCacheEntry),
		retryAttempts: make(map[string]int),
		retryTimers:   make(map[string]*time.Timer),
	}

	log.Printf("Initialized Policy File Loader (%s)", dir)

	// Initial sweep.
	entries, err := os.ReadDir(dir)
	if err != nil {
		_ = w.Close()
		cancel()
		return nil, fmt.Errorf("failed to list %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !isYAMLFile(e.Name()) {
			continue
		}
		l.loadAndApply(knox, filepath.Join(dir, e.Name()))
	}

	knox.WgDaemon.Add(1)
	go func() {
		defer knox.WgDaemon.Done()
		l.watchLoop(knox)
	}()

	return l, nil
}

// Close stops the watcher goroutine and releases the inotify handle.
func (l *PolicyFileLoader) Close() {
	if l == nil {
		return
	}
	l.cancel()
	if l.watcher != nil {
		_ = l.watcher.Close()
	}
	l.mu.Lock()
	for _, t := range l.retryTimers {
		t.Stop()
	}
	l.retryTimers = map[string]*time.Timer{}
	l.retryAttempts = map[string]int{}
	l.mu.Unlock()
	log.Print("Stopped Policy File Loader")
}

func (l *PolicyFileLoader) watchLoop(knox *KloudKnox) {
	for {
		select {
		case <-l.ctx.Done():
			return
		case ev, ok := <-l.watcher.Events:
			if !ok {
				return
			}
			if !isYAMLFile(ev.Name) {
				continue
			}
			switch {
			case ev.Op&(fsnotify.Create|fsnotify.Write) != 0:
				l.loadAndApply(knox, ev.Name)
			case ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0:
				l.removeFile(knox, ev.Name)
			}
		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			log.Errf("Policy watcher error: %v", err)
		}
	}
}

// isYAMLFile matches regular ".yaml"/".yml" files only. Dotfiles (names
// starting with ".") are filtered so atomic write-then-rename temp files
// authored by kkctl — e.g. ".nginx.yaml.1234567890" — never trigger the
// loader mid-write. Only the final rename to the non-dot name is observed.
func isYAMLFile(name string) bool {
	base := filepath.Base(name)
	if strings.HasPrefix(base, ".") {
		return false
	}
	switch strings.ToLower(filepath.Ext(base)) {
	case ".yaml", ".yml":
		return true
	}
	return false
}

// Policy read/apply

// loadAndApply parses one file (possibly multi-document) and reconciles the
// cache so that policies added/removed/modified by this edit land in the
// runtime state exactly once.
func (l *PolicyFileLoader) loadAndApply(knox *KloudKnox, path string) {
	policies, err := readPolicyFile(path)
	if err != nil {
		l.scheduleRetry(knox, path, err)
		return
	}
	l.resetRetry(path)

	l.mu.Lock()
	prev := l.cache[path]
	l.mu.Unlock()

	prevByKey := map[string]policyCacheEntry{}
	for _, e := range prev {
		prevByKey[e.namespace+"/"+e.name] = e
	}

	newEntries := make([]policyCacheEntry, 0, len(policies))
	for _, p := range policies {
		// Derive stable identifier when CRD metadata is missing.
		if p.UID == "" {
			p.UID = uidFromFile(path, p.Namespace, p.Name)
		}
		if p.Namespace == "" {
			p.Namespace = cfg.GlobalCfg.DefaultNS
		}

		converted := convertKloudKnoxPolicy(&p)
		key := converted.NamespaceName + "/" + converted.PolicyName

		upsertKloudKnoxPolicy(knox, converted)
		applyKloudKnoxPolicyToPods(knox, converted)
		log.Printf("Applied a KloudKnoxPolicy from %s (%s)", filepath.Base(path), key)

		newEntries = append(newEntries, policyCacheEntry{
			namespace: converted.NamespaceName,
			name:      converted.PolicyName,
			policy:    converted,
		})
		delete(prevByKey, key)
	}

	// Anything left in prevByKey was removed by this edit.
	for _, stale := range prevByKey {
		removeKloudKnoxPolicy(knox, stale.policy)
		removeKloudKnoxPolicyFromPods(knox, stale.policy)
		log.Printf("Removed a KloudKnoxPolicy from %s (%s/%s)",
			filepath.Base(path), stale.namespace, stale.name)
	}

	l.mu.Lock()
	l.cache[path] = newEntries
	l.mu.Unlock()
}

// removeFile drops every policy the given file had contributed.
func (l *PolicyFileLoader) removeFile(knox *KloudKnox, path string) {
	l.mu.Lock()
	entries := l.cache[path]
	delete(l.cache, path)
	l.mu.Unlock()

	l.resetRetry(path)

	for _, e := range entries {
		removeKloudKnoxPolicy(knox, e.policy)
		removeKloudKnoxPolicyFromPods(knox, e.policy)
		log.Printf("Removed a KloudKnoxPolicy from %s (%s/%s)",
			filepath.Base(path), e.namespace, e.name)
	}
}

// scheduleRetry arms a debounce timer to re-read a file that just failed to
// parse. A WRITE event arriving while an external editor is still writing
// will yield a partial document; giving it policyRetryDelay to settle avoids
// flapping rejection log lines. After policyMaxRetryTries, the loader gives
// up and emits a single warning — the operator can fix the file and the
// next CREATE/WRITE event will reset the counter.
func (l *PolicyFileLoader) scheduleRetry(knox *KloudKnox, path string, cause error) {
	l.mu.Lock()
	attempts := l.retryAttempts[path] + 1
	l.retryAttempts[path] = attempts
	if t, ok := l.retryTimers[path]; ok {
		t.Stop()
		delete(l.retryTimers, path)
	}
	if attempts > policyMaxRetryTries {
		delete(l.retryAttempts, path)
		l.mu.Unlock()
		log.Errf("Policy file %s rejected after %d attempts: %v",
			path, policyMaxRetryTries, cause)
		return
	}
	t := time.AfterFunc(policyRetryDelay, func() {
		select {
		case <-l.ctx.Done():
			return
		default:
		}
		l.loadAndApply(knox, path)
	})
	l.retryTimers[path] = t
	l.mu.Unlock()
	log.Printf("Policy file %s parse failed (attempt %d/%d), retrying: %v",
		path, attempts, policyMaxRetryTries, cause)
}

// resetRetry clears retry bookkeeping for a file that parsed successfully or
// was removed.
func (l *PolicyFileLoader) resetRetry(path string) {
	l.mu.Lock()
	if t, ok := l.retryTimers[path]; ok {
		t.Stop()
		delete(l.retryTimers, path)
	}
	delete(l.retryAttempts, path)
	l.mu.Unlock()
}

// readPolicyFile parses a YAML file into one or more KloudKnoxPolicy objects.
// Separates documents on "---" so a single file can carry a bundle.
func readPolicyFile(path string) ([]securityv1.KloudKnoxPolicy, error) {
	// #nosec G304 — the caller validated path against the watch directory.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	dec := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []securityv1.KloudKnoxPolicy
	for {
		var p securityv1.KloudKnoxPolicy
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if p.Name == "" && p.Kind == "" {
			// Empty document separator in the stream — skip.
			continue
		}
		if p.Kind != "" && p.Kind != "KloudKnoxPolicy" {
			return nil, fmt.Errorf("unexpected kind %q", p.Kind)
		}
		if p.Name == "" {
			return nil, errors.New("metadata.name is required")
		}
		if err := securityv1.ValidateSpec(&p.Spec); err != nil {
			return nil, fmt.Errorf("policy %s: %w", p.Name, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// uidFromFile derives a deterministic UID for policies that lack CRD-assigned
// metadata — e.g. ones authored by hand for standalone mode.
func uidFromFile(path, ns, name string) k8stypes.UID {
	base := filepath.Clean(path) + "|" + ns + "/" + name
	return k8stypes.UID(base)
}
