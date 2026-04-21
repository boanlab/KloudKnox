// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"testing"
)

// ============================== //
// ==  isYAMLFile Tests        == //
// ============================== //

func TestIsYAMLFile(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"plain yaml", "nginx.yaml", true},
		{"plain yml", "nginx.yml", true},
		{"upper-case YAML", "Nginx.YAML", true},
		{"full path yaml", "/etc/kloudknox/policies/nginx.yaml", true},

		{"non-yaml extension", "nginx.json", false},
		{"no extension", "nginx", false},
		{"empty", "", false},

		// Dotfiles must be skipped so atomic write temp files created by
		// kkctl (".nginx.yaml.1234567890") never trigger the loader.
		{"dotfile with random tail", ".nginx.yaml.1234567890", false},
		{"dotfile with full yaml name", ".nginx.yaml", false},
		{"dotfile in subpath", "/tmp/policies/.tmp.yaml", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isYAMLFile(tc.in); got != tc.want {
				t.Errorf("isYAMLFile(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
