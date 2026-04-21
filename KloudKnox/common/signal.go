// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package common

import "strings"

// SignalNameToNumber maps the symbolic name (e.g. "SIGTERM") to its Linux
// signal number. Matches asm-generic/signal.h on x86_64 and is kept in sync
// with operator-controller/api/v1/kloudknoxpolicy_validation.go:validSignals.
//
// RT signals (SIGRTMIN+N) are intentionally omitted — they're rare as policy
// targets and would need kernel-specific offsets.
var SignalNameToNumber = map[string]int{
	"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5,
	"SIGABRT": 6, "SIGBUS": 7, "SIGFPE": 8, "SIGKILL": 9, "SIGUSR1": 10,
	"SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13, "SIGALRM": 14, "SIGTERM": 15,
	"SIGCHLD": 17, "SIGCONT": 18, "SIGSTOP": 19, "SIGTSTP": 20,
	"SIGTTIN": 21, "SIGTTOU": 22, "SIGURG": 23, "SIGXCPU": 24, "SIGXFSZ": 25,
	"SIGVTALRM": 26, "SIGPROF": 27, "SIGWINCH": 28, "SIGIO": 29, "SIGPWR": 30,
	"SIGSYS": 31,
}

// signalNumberToName is built at init time for reverse lookup. It only holds
// symbols that SignalNameToNumber can round-trip.
var signalNumberToName = func() map[int]string {
	m := make(map[int]string, len(SignalNameToNumber))
	for name, num := range SignalNameToNumber {
		m[num] = name
	}
	return m
}()

// SignalNumber normalizes a user-supplied signal token ("SIGTERM", "sigterm",
// "TERM") to its Linux number. Returns (0, false) when the token does not
// resolve to a known signal.
func SignalNumber(name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	upper := strings.ToUpper(name)
	if !strings.HasPrefix(upper, "SIG") {
		upper = "SIG" + upper
	}
	n, ok := SignalNameToNumber[upper]
	return n, ok
}

// SignalName returns the canonical "SIG*" symbol for a signal number, or an
// empty string for numbers that SignalNameToNumber does not cover.
func SignalName(n int) string {
	return signalNumberToName[n]
}

// AppArmorSignalToken returns the short AppArmor token for a given signal
// name (e.g. "SIGTERM" -> "term"). AppArmor's `signal set=(...)` syntax uses
// the lowercase form without the SIG prefix.
func AppArmorSignalToken(name string) string {
	upper := strings.ToUpper(name)
	upper = strings.TrimPrefix(upper, "SIG")
	return strings.ToLower(upper)
}
