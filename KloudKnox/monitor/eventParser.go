// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package monitor

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// Event is the structure of the event data captured by eBPF programs
type Event struct {
	Timestamp uint64

	CPUID  uint32
	SeqNum uint32

	PidNsID uint32
	MntNsID uint32

	HostPPID int32
	HostPID  int32
	HostTID  int32

	PPID int32
	PID  int32
	TID  int32

	UID uint32
	GID uint32

	EventID   int16
	EventType int8
	ArgNum    int8
	RetVal    int32
}

// EventType is the type of the event
const (
	EventTypeUnary = iota
	EventTypeEnter
	EventTypeExit
)

// Type is the type of the argument data
const (
	TypeNone uint32 = iota
	TypeInt
	TypeUInt
	TypeULong
	TypeStr
	TypeStrArr
	TypeSource
	TypeResource
)

// readEventFromBuff reads the event data from the buffer
func readEventFromBuff(data io.Reader) (Event, error) {
	var res Event
	err := binary.Read(data, binary.LittleEndian, &res)
	return res, err
}

// Generic read function for numeric types to reduce code duplication
func readNumericFromBuff[T any](data io.Reader) (T, error) {
	var res T
	err := binary.Read(data, binary.LittleEndian, &res)
	return res, err
}

// readInt32FromBuff reads the int32 data from the buffer
func readInt32FromBuff(data io.Reader) (int32, error) {
	return readNumericFromBuff[int32](data)
}

// readUInt32FromBuff reads the uint32 data from the buffer
func readUInt32FromBuff(data io.Reader) (uint32, error) {
	return readNumericFromBuff[uint32](data)
}

// readUInt64FromBuff reads the uint64 data from the buffer
func readUInt64FromBuff(data io.Reader) (uint64, error) {
	return readNumericFromBuff[uint64](data)
}

// readStringFromBuff reads the string data from the buffer
func readStringFromBuff(data io.Reader) (string, error) {
	size, err := readUInt32FromBuff(data)
	if err != nil {
		return "", fmt.Errorf("failed to read string length: %v", err)
	}

	if size == 0 {
		return "unknown", nil
	}

	// Limit string size to prevent memory exhaustion
	if size > 2048 {
		return "", fmt.Errorf("string too large: %d bytes", size)
	}

	// Pre-allocate buffer with exact size to avoid reallocation
	res := make([]byte, size)
	if _, err := io.ReadFull(data, res); err != nil {
		return "", fmt.Errorf("failed to read string data: %v", err)
	}

	// More efficient null trimming - find last non-null byte
	lastNonNull := len(res) - 1
	for lastNonNull >= 0 && res[lastNonNull] == 0 {
		lastNonNull--
	}

	return string(res[:lastNonNull+1]), nil
}

// readArgFromBuff reads the argument data from the buffer
func readArgFromBuff(data io.Reader) (interface{}, error) {
	tp, err := readUInt32FromBuff(data)
	if err != nil {
		return nil, err
	}

	switch tp {
	case TypeInt:
		return readInt32FromBuff(data)
	case TypeUInt:
		return readUInt32FromBuff(data)
	case TypeULong:
		return readUInt64FromBuff(data)
	case TypeStr, TypeSource, TypeResource:
		return readStringFromBuff(data)
	case TypeStrArr:
		return readStringArrayFromBuff(data)

	default:
		return nil, fmt.Errorf("unknown type: %d", tp)
	}
}

// readStringArrayFromBuff reads string array from buffer
func readStringArrayFromBuff(data io.Reader) ([]string, error) {
	args := make([]string, 0, 8)
	count := 0
	const maxArgs = 256 // Limit to prevent infinite loops

	for {
		if count >= maxArgs {
			return nil, fmt.Errorf("too many arguments in string array: %d", count)
		}
		count++

		argType, err := readUInt32FromBuff(data)
		if err != nil {
			return nil, fmt.Errorf("failed to read arg type: %v", err)
		}

		if argType == 0 {
			break
		}

		arg, err := readStringFromBuff(data)
		if err != nil {
			return nil, fmt.Errorf("failed to read arg: %v", err)
		}

		args = append(args, arg)
	}

	return args, nil
}

// Argument Parsing

// safeString converts interface{} to string safely
func safeString(v interface{}) string {
	if v == nil {
		return "unknown"
	}
	if str, ok := v.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", v)
}

// safeStringSlice converts interface{} to []string safely
func safeStringSlice(v interface{}) []string {
	if v == nil {
		return []string{"unknown"}
	}
	if slice, ok := v.([]string); ok {
		return slice
	}
	return []string{fmt.Sprintf("%v", v)}
}

// safeInt32 converts interface{} to int32 safely
func safeInt32(v interface{}) int32 {
	if val, ok := v.(int32); ok {
		return val
	}
	return 0
}

// safeUint32 converts interface{} to uint32 safely
func safeUint32(v interface{}) uint32 {
	if val, ok := v.(uint32); ok {
		return val
	}
	return 0
}

// safeUint64 converts interface{} to uint64 safely
func safeUint64(v interface{}) uint64 {
	if val, ok := v.(uint64); ok {
		return val
	}
	return 0
}

// getArgs gets the arguments from the buffer
func (m *SystemMonitor) getArgs(data io.Reader, evData *tp.EventData) error {
	argNum := evData.ArgNum

	if argNum <= 0 {
		return nil
	}

	args := make([]interface{}, 0, argNum)

	for i := int32(0); i < argNum; i++ {
		arg, err := readArgFromBuff(data)
		if err != nil {
			return fmt.Errorf("failed to read argument %d: %v (syscall: %s (%d), args: %v)", i, err, evData.EventName, evData.EventID, args)
		}
		if arg == nil {
			break
		}
		args = append(args, arg)
	}

	switch evData.EventName {

	// Process events

	case "clone", "clone3":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "clone"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("flags: %s", getCloneFlags(safeUint64(args[0])))
		}

	case "execve":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "execute"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("cmd: %s", strings.Join(safeStringSlice(args[1])[:], " "))
			if env := extractSuspiciousEnv(safeStringSlice(args[2])); env != "" {
				evData.Data += fmt.Sprintf(", env: %s", env)
			}
		}

	case "execveat":
		if argNum == 6 {
			source := safeString(args[5])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "execute"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("cmd: %s, flags: %s",
				strings.Join(safeStringSlice(args[2])[:], " "), getExecveAtFlags(safeInt32(args[4])))
			if env := extractSuspiciousEnv(safeStringSlice(args[3])); env != "" {
				evData.Data += fmt.Sprintf(", env: %s", env)
			}
		}

	case "security_bprm_check": // internal update
		if argNum == 1 {
			key1 := int64(evData.HostTID)<<16 | sysExecve

			if origEvData1, ok := m.getEventData(key1); ok {
				if !strings.HasPrefix(origEvData1.Resource, "/") {
					origEvData1.Resource = safeString(args[0])
					m.setEventData(key1, origEvData1)

					// update the path to the pidMap
					m.updatePathToPidMap(origEvData1.HostPID, origEvData1.Resource)

					return nil
				}
			}

			key2 := int64(evData.HostTID)<<16 | sysExecveat

			if origEvData2, ok := m.getEventData(key2); ok {
				if !strings.HasPrefix(origEvData2.Resource, "/") {
					origEvData2.Resource = safeString(args[0])
					m.setEventData(key2, origEvData2)

					// update the path to the pidMap
					m.updatePathToPidMap(origEvData2.HostPID, origEvData2.Resource)

					return nil
				}
			}
		}

	case "exit", "exit_group":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "exit"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("error code: %d", safeInt32(args[0]))
		}

	case "sched_process_exit": // EVENT_UNARY
		if argNum == 1 {
			source := safeString(args[0])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}

			evData.Category = "process"
			evData.Operation = "exit"
			evData.Resource = evData.Source
		}

	case "setuid":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setuid"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("uid: %d", safeUint32(args[0]))
		}

	case "setreuid":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setuid"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("ruid: %d, euid: %d", safeUint32(args[0]), safeUint32(args[1]))
		}

	case "setresuid":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setuid"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("ruid: %d, euid: %d, suid: %d", safeUint32(args[0]), safeUint32(args[1]), safeUint32(args[2]))
		}

	case "setfsuid":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setuid"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("fsuid: %d", safeUint32(args[0]))
		}

	case "setgid":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setgid"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("gid: %d", safeUint32(args[0]))
		}

	case "setregid":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setgid"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("rgid: %d, egid: %d", safeUint32(args[0]), safeUint32(args[1]))
		}

	case "setresgid":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setgid"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("rgid: %d, egid: %d, sgid: %d", safeUint32(args[0]), safeUint32(args[1]), safeUint32(args[2]))
		}

	case "setfsgid":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setgid"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("fsgid: %d", safeUint32(args[0]))
		}

	case "kill":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "kill"
			if evData.HostPID == safeInt32(args[0]) {
				evData.Resource = evData.Source
			} else {
				evData.Resource = m.getPathFromPidMap(safeInt32(args[0]))
			}
			evData.Data = fmt.Sprintf("pid: %d, sig: %s", safeInt32(args[0]), getSignal(safeInt32(args[1])))
		}

	case "tgkill":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "kill"
			if evData.HostPID == safeInt32(args[0]) {
				evData.Resource = evData.Source
			} else {
				evData.Resource = m.getPathFromPidMap(safeInt32(args[0]))
			}
			evData.Data = fmt.Sprintf("pid: %d, tid: %d, sig: %s", safeInt32(args[0]), safeInt32(args[1]), getSignal(safeInt32(args[2])))
		}

	case "security_task_kill": // internal update
		if argNum == 1 {
			key1 := int64(evData.HostTID)<<16 | sysKill

			if origEvData1, ok := m.getEventData(key1); ok {
				origEvData1.Resource = safeString(args[0])
				m.setEventData(key1, origEvData1)
				return nil
			}

			key2 := int64(evData.HostTID)<<16 | sysTgkill

			if origEvData2, ok := m.getEventData(key2); ok {
				origEvData2.Resource = safeString(args[0])
				m.setEventData(key2, origEvData2)
				return nil
			}
		}

	case "unshare":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "unshare"
			evData.Data = fmt.Sprintf("flags: %s", getUnshareFlags(safeInt32(args[0])))
		}

	case "setns":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setns"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("fd: %d, nstype: %s", safeInt32(args[0]), getSetNSType(safeInt32(args[1])))
		}

	case "setrlimit":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "setrlimit"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("resource: %s, rlim_cur: %d, rlim_max: %d",
				getRlimitResource(safeUint32(args[0])), safeUint64(args[1]), safeUint64(args[2]))
		}

	case "chroot":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "chroot"
			evData.Resource = safeString(args[0])
		}

	case "security_path_chroot": // internal update
		if argNum == 1 {
			key1 := int64(evData.HostTID)<<16 | sysChroot

			if origEvData1, ok := m.getEventData(key1); ok {
				if !strings.HasPrefix(origEvData1.Resource, "/") {
					origEvData1.Resource = safeString(args[0])
					m.setEventData(key1, origEvData1)

					return nil
				}
			}
		}

	case "capset":
		if argNum == 5 {
			source := safeString(args[4])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "capset"
			if (safeInt32(args[0]) == 0) || (safeInt32(args[0]) == evData.HostPID) {
				evData.Resource = evData.Source
			} else {
				evData.Resource = m.getPathFromPidMap(safeInt32(args[0]))
			}
			evData.Data = fmt.Sprintf("pid: %d, effective: %s, permitted: %s, inheritable: %s",
				args[0], getCapabilities(safeUint32(args[1])), getCapabilities(safeUint32(args[2])), getCapabilities(safeUint32(args[3])))
		}

	case "ptrace":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "process"
			evData.Operation = "ptrace"
			evData.Resource = evData.Source
			evData.Data = fmt.Sprintf("request: %s, pid: %d", getPtraceRequest(safeInt32(args[0])), safeInt32(args[1]))
		}

	// kprobe/cap_capable (event id __SECURITY_CAPABLE) — capability usage
	// attempts. The probe fires at function entry, so the event carries no
	// allow/deny retval; policyMatcher treats a matching rule as pure
	// attribution ("this cap was used under rule X").
	case "security_capable":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			capID := safeInt32(args[0])
			evData.Category = "capability"
			evData.Operation = "capable"
			evData.Resource = lib.CapabilityName(uint32(capID)) // #nosec G115 -- capID is a kernel capability id in [0, 63], never negative
			if evData.Resource == "" {
				evData.Resource = fmt.Sprintf("CAP_%d", capID)
			}
			evData.Data = fmt.Sprintf("cap: %d, audit: %d", capID, safeInt32(args[1]))
		}

	// kprobe/security_unix_stream_connect — client-side connect() on a unix
	// stream socket. args[0] is the peer sun_path (abstract sockets arrive
	// "@name"; lib.FNV1a64UnixPath matches them on the kernel side).
	case "security_unix_stream_connect":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "ipc"
			evData.Operation = "unix_connect"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("type: stream, peer: %s", evData.Resource)
		}

	// kprobe/security_unix_may_send — per-datagram send() on a unix dgram
	// socket. Shares the same resource shape as unix_connect.
	case "security_unix_may_send":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "ipc"
			evData.Operation = "unix_send"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("type: dgram, peer: %s", evData.Resource)
		}

	// kprobe/security_ptrace_access_check — tracer/tracee relationship check.
	// args[0] carries the mode (PTRACE_MODE_READ / PTRACE_MODE_ATTACH), args[1]
	// the tracee comm / path if resolvable. Signal events are handled by
	// security_task_kill (Operation="kill"), not here.
	case "security_ptrace_access_check":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "ipc"
			evData.Operation = "ptrace"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("mode: %#x, peer: %s", safeUint32(args[0]), evData.Resource)
		}

	// File events

	case "open":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "open"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("flags: %s, mode: %s", getOpenFlags(safeInt32(args[1])), getMode(safeUint32(args[2])))
		}

	case "openat":
		if argNum == 5 {
			source := safeString(args[4])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "open"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("flags: %s, mode: %s",
				getOpenFlags(safeInt32(args[2])), getMode(safeUint32(args[3])))
		}

	case "openat2":
		if argNum == 6 {
			source := safeString(args[5])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "open"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("flags: %s, mode: %s, resolve: %s",
				getOpenFlags(safeInt32(args[2])), getMode(safeUint32(args[3])), getResolveFlags(safeUint64(args[4])))
		}

	case "security_file_open": // internal update
		if argNum == 2 {
			key1 := int64(evData.HostTID)<<16 | sysOpen

			if origEvData1, ok := m.getEventData(key1); ok {
				if !strings.HasPrefix(origEvData1.Resource, "/") {
					switch safeString(args[0]) {
					case "proc":
						origEvData1.Resource = "/proc" + safeString(args[1])
					case "cgroup2":
						origEvData1.Resource = "/sys/fs/cgroup" + safeString(args[1])
					case "securityfs":
						origEvData1.Resource = "/sys/kernel/security" + safeString(args[1])
					case "devpts":
						origEvData1.Resource = "/dev/pts" + safeString(args[1])
					case "devtmpfs":
						origEvData1.Resource = "/dev" + safeString(args[1])
					case "sysfs":
						origEvData1.Resource = "/sys" + safeString(args[1])
					case "tmpfs":
						if strings.HasPrefix(safeString(args[1]), "/null") {
							origEvData1.Resource = "/dev" + safeString(args[1])
						} else if strings.HasPrefix(safeString(args[1]), "/systemd") {
							origEvData1.Resource = "/run" + safeString(args[1])
						} else {
							origEvData1.Resource = "(tmpfs)" + safeString(args[1])
						}
					default:
						origEvData1.Resource = safeString(args[1])
					}
					m.setEventData(key1, origEvData1)

					// update the path to the fdMap
					m.updatePathToFdMap(origEvData1.HostPID, origEvData1.RetVal, origEvData1.Resource)

					return nil
				}
			}

			key2 := int64(evData.HostTID)<<16 | sysOpenat

			if origEvData2, ok := m.getEventData(key2); ok {
				if !strings.HasPrefix(origEvData2.Resource, "/") {
					switch safeString(args[0]) {
					case "proc":
						origEvData2.Resource = "/proc" + safeString(args[1])
					case "cgroup2":
						origEvData2.Resource = "/sys/fs/cgroup" + safeString(args[1])
					case "securityfs":
						origEvData2.Resource = "/sys/kernel/security" + safeString(args[1])
					case "devpts":
						origEvData2.Resource = "/dev/pts" + safeString(args[1])
					case "devtmpfs":
						origEvData2.Resource = "/dev" + safeString(args[1])
					case "sysfs":
						origEvData2.Resource = "/sys" + safeString(args[1])
					case "tmpfs":
						if strings.HasPrefix(safeString(args[1]), "/null") {
							origEvData2.Resource = "/dev" + safeString(args[1])
						} else if strings.HasPrefix(safeString(args[1]), "/systemd") {
							origEvData2.Resource = "/run" + safeString(args[1])
						} else {
							origEvData2.Resource = "(tmpfs)" + safeString(args[1])
						}
					default:
						origEvData2.Resource = safeString(args[1])
					}
					m.setEventData(key2, origEvData2)

					// update the path to the fdMap
					m.updatePathToFdMap(origEvData2.HostPID, origEvData2.RetVal, origEvData2.Resource)

					return nil
				}
			}

			key3 := int64(evData.HostTID)<<16 | sysOpenat2

			if origEvData3, ok := m.getEventData(key3); ok {
				if !strings.HasPrefix(origEvData3.Resource, "/") {
					switch safeString(args[0]) {
					case "proc":
						origEvData3.Resource = "/proc" + safeString(args[1])
					case "cgroup2":
						origEvData3.Resource = "/sys/fs/cgroup" + safeString(args[1])
					case "securityfs":
						origEvData3.Resource = "/sys/kernel/security" + safeString(args[1])
					case "devpts":
						origEvData3.Resource = "/dev/pts" + safeString(args[1])
					case "devtmpfs":
						origEvData3.Resource = "/dev" + safeString(args[1])
					case "sysfs":
						origEvData3.Resource = "/sys" + safeString(args[1])
					case "tmpfs":
						if strings.HasPrefix(safeString(args[1]), "/null") {
							origEvData3.Resource = "/dev" + safeString(args[1])
						} else if strings.HasPrefix(safeString(args[1]), "/systemd") {
							origEvData3.Resource = "/run" + safeString(args[1])
						} else {
							origEvData3.Resource = "(tmpfs)" + safeString(args[1])
						}
					default:
						origEvData3.Resource = safeString(args[1])
					}
					m.setEventData(key3, origEvData3)

					// update the path to the fdMap
					m.updatePathToFdMap(origEvData3.HostPID, origEvData3.RetVal, origEvData3.Resource)

					return nil
				}
			}
		}

	case "close":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "close"
			evData.Resource = m.getPathFromFdMap(evData.HostPID, safeInt32(args[0]))
			evData.Data = fmt.Sprintf("fd: %d", safeInt32(args[0]))
			evData.TempInt32 = safeInt32(args[0]) // fd preserved for EXIT handler cleanup
		}

	case "filp_close": // internal update
		if argNum == 2 {
			key1 := int64(evData.HostTID)<<16 | sysClose

			if origEvData1, ok := m.getEventData(key1); ok {
				switch safeString(args[0]) {
				case "proc":
					origEvData1.Resource = "/proc" + safeString(args[1])
				case "cgroup2":
					origEvData1.Resource = "/sys/fs/cgroup" + safeString(args[1])
				case "securityfs":
					origEvData1.Resource = "/sys/kernel/security" + safeString(args[1])
				case "devpts":
					origEvData1.Resource = "/dev/pts" + safeString(args[1])
				case "devtmpfs":
					origEvData1.Resource = "/dev" + safeString(args[1])
				case "sysfs":
					origEvData1.Resource = "/sys" + safeString(args[1])
				case "tmpfs":
					if strings.HasPrefix(safeString(args[1]), "/null") {
						origEvData1.Resource = "/dev" + safeString(args[1])
					} else if strings.HasPrefix(safeString(args[1]), "/systemd") {
						origEvData1.Resource = "/run" + safeString(args[1])
					} else {
						origEvData1.Resource = "(tmpfs)" + safeString(args[1])
					}
				default:
					origEvData1.Resource = safeString(args[1])
				}

				m.setEventData(key1, origEvData1)

				return nil
			}
		}

	case "chown":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "chown"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("uid: %d, gid: %d", safeUint32(args[1]), safeUint32(args[2]))
		}

	case "fchown":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "chown"
			evData.Resource = m.getPathFromFdMap(evData.HostPID, safeInt32(args[0]))
			evData.Data = fmt.Sprintf("fd: %d, uid: %d, gid: %d", safeInt32(args[0]), safeUint32(args[1]), safeUint32(args[2]))
		}

	case "fchownat":
		if argNum == 6 {
			source := safeString(args[5])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "chown"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("uid: %d, gid: %d, flags: %s",
				safeUint32(args[2]), safeUint32(args[3]), getFchownAtFlags(safeInt32(args[4])))
		}

	case "security_path_chown": // internal update
		if argNum == 1 {
			key1 := int64(evData.HostTID)<<16 | sysChown

			if origEvData1, ok := m.getEventData(key1); ok {
				if !strings.HasPrefix(origEvData1.Resource, "/") {
					origEvData1.Resource = safeString(args[0])
					m.setEventData(key1, origEvData1)

					return nil
				}
			}

			key2 := int64(evData.HostTID)<<16 | sysFchownat

			if origEvData2, ok := m.getEventData(key2); ok {
				if !strings.HasPrefix(origEvData2.Resource, "/") {
					origEvData2.Resource = safeString(args[0])
					m.setEventData(key2, origEvData2)

					return nil
				}
			}
		}

	case "chmod":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "chmod"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("mode: %s", getMode(safeUint32(args[1])))
		}

	case "fchmod":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "chmod"
			evData.Resource = m.getPathFromFdMap(evData.HostPID, safeInt32(args[0]))
			evData.Data = fmt.Sprintf("fd: %d, mode: %s", safeInt32(args[0]), getMode(safeUint32(args[1])))
		}

	case "fchmodat":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "chmod"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("mode: %s", getMode(safeUint32(args[2])))
		}

	case "security_path_chmod": // internal update
		if argNum == 1 {
			key1 := int64(evData.HostTID)<<16 | sysChmod

			if origEvData1, ok := m.getEventData(key1); ok {
				if !strings.HasPrefix(origEvData1.Resource, "/") {
					origEvData1.Resource = safeString(args[0])
					m.setEventData(key1, origEvData1)

					return nil
				}
			}

			key2 := int64(evData.HostTID)<<16 | sysFchmodat

			if origEvData2, ok := m.getEventData(key2); ok {
				if !strings.HasPrefix(origEvData2.Resource, "/") {
					origEvData2.Resource = safeString(args[0])
					m.setEventData(key2, origEvData2)

					return nil
				}
			}
		}

	case "unlink":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "unlink"
			evData.Resource = safeString(args[0])
		}

	case "unlinkat":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "unlink"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("flags: %s", getUnlinkAtFlags(safeInt32(args[2])))
		}

	case "security_path_unlink": // internal update
		if argNum == 1 {
			key1 := int64(evData.HostTID)<<16 | sysUnlink

			if origEvData1, ok := m.getEventData(key1); ok {
				if !strings.HasPrefix(origEvData1.Resource, "/") {
					origEvData1.Resource = safeString(args[0])
					m.setEventData(key1, origEvData1)

					return nil
				}
			}

			key2 := int64(evData.HostTID)<<16 | sysUnlinkat

			if origEvData2, ok := m.getEventData(key2); ok {
				if !strings.HasPrefix(origEvData2.Resource, "/") {
					origEvData2.Resource = safeString(args[0])
					m.setEventData(key2, origEvData2)

					return nil
				}
			}
		}

	case "rename", "renameat":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "rename"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("old_path: %s, new_path: %s", args[0], args[1])
		}

	case "renameat2":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "rename"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("old_path: %s, new_path: %s, flags: %s", args[0], args[1], getRenameAt2Flags(safeUint32(args[2])))
			evData.TempUint32 = safeUint32(args[2])
		}

	case "security_path_rename": // internal update
		if argNum == 2 {
			key1 := int64(evData.HostTID)<<16 | sysRename

			if origEvData1, ok := m.getEventData(key1); ok {
				origEvData1.Resource = safeString(args[0])
				origEvData1.Data = fmt.Sprintf("old_path: %s, new_path: %s", args[0], args[1])
				m.setEventData(key1, origEvData1)

				return nil
			}

			key2 := int64(evData.HostTID)<<16 | sysRenameat

			if origEvData2, ok := m.getEventData(key2); ok {
				origEvData2.Resource = safeString(args[0])
				origEvData2.Data = fmt.Sprintf("old_path: %s, new_path: %s", args[0], args[1])
				m.setEventData(key2, origEvData2)

				return nil
			}

			key3 := int64(evData.HostTID)<<16 | sysRenameat2

			if origEvData3, ok := m.getEventData(key3); ok {
				origEvData3.Resource = safeString(args[0])
				origEvData3.Data = fmt.Sprintf("old_path: %s, new_path: %s, flags: %s", args[0], args[1], getRenameAt2Flags(origEvData3.TempUint32))
				m.setEventData(key3, origEvData3)

				return nil
			}
		}

	case "link":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "link"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("path: %s, link: %s", args[0], args[1])
		}

	case "linkat":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "link"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("path: %s, link: %s, flags: %s", args[0], args[1], getLinkAtFlags(safeInt32(args[2])))
			evData.TempInt32 = safeInt32(args[2]) // flags
		}

	case "security_path_link": // internal update
		if argNum == 2 {
			key1 := int64(evData.HostTID)<<16 | sysLink

			if origEvData1, ok := m.getEventData(key1); ok {
				origEvData1.Resource = safeString(args[0])
				origEvData1.Data = fmt.Sprintf("path: %s, link: %s", args[0], args[1])
				m.setEventData(key1, origEvData1)

				return nil
			}

			key2 := int64(evData.HostTID)<<16 | sysLinkat

			if origEvData2, ok := m.getEventData(key2); ok {
				origEvData2.Resource = safeString(args[0])
				origEvData2.Data = fmt.Sprintf("path: %s, link: %s, flags: %s", args[0], args[1], getLinkAtFlags(origEvData2.TempInt32))
				m.setEventData(key2, origEvData2)

				return nil
			}
		}

	case "symlink", "symlinkat":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "symlink"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("path: %s, symlink: %s", safeString(args[0]), safeString(args[1]))
		}

	case "mkdir":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "mkdir"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("mode: %s", getMode(safeUint32(args[1])))
		}

	case "mkdirat":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "mkdir"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("mode: %s", getMode(safeUint32(args[2])))
		}

	case "security_path_mkdir": // internal update
		if argNum == 1 {
			key1 := int64(evData.HostTID)<<16 | sysMkdir

			if origEvData1, ok := m.getEventData(key1); ok {
				if !strings.HasPrefix(origEvData1.Resource, "/") {
					origEvData1.Resource = safeString(args[0])
					m.setEventData(key1, origEvData1)

					return nil
				}
			}

			key2 := int64(evData.HostTID)<<16 | sysMkdirat

			if origEvData2, ok := m.getEventData(key2); ok {
				if !strings.HasPrefix(origEvData2.Resource, "/") {
					origEvData2.Resource = safeString(args[0])
					m.setEventData(key2, origEvData2)

					return nil
				}
			}
		}

	case "rmdir":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "rmdir"
			evData.Resource = safeString(args[0])
		}

	case "security_path_rmdir": // internal update
		if argNum == 1 {
			key1 := int64(evData.HostTID)<<16 | sysRmdir

			if origEvData1, ok := m.getEventData(key1); ok {
				if !strings.HasPrefix(origEvData1.Resource, "/") {
					origEvData1.Resource = safeString(args[0])
					m.setEventData(key1, origEvData1)

					return nil
				}
			}
		}

	case "mount":
		if argNum == 5 {
			source := safeString(args[4])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "mount"
			evData.Resource = safeString(args[1])
			evData.Data = fmt.Sprintf("dev_name: %s, dir_name: %s, type: %s, flags: %s",
				args[0], args[1], args[2], getMountFlags(safeUint64(args[3])))
		}

	case "umount2":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}
			evData.Category = "file"
			evData.Operation = "umount"
			evData.Resource = safeString(args[0])
			evData.Data = fmt.Sprintf("flags: %s", getMountFlags(safeUint64(args[1])))
		}

	// Network Events

	case "socket":
		if argNum == 4 {
			source := safeString(args[3])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}

			saFamily := getSocketFamily(safeInt32(args[0]))
			sockType := getSocketType(safeInt32(args[1]))
			sockFlags := getSocketFlags(safeInt32(args[1]))
			sockProtocol := getSocketProtocol(safeInt32(args[0]), safeInt32(args[1]), safeInt32(args[2]))

			evData.Category = "network"
			evData.Operation = "socket"
			evData.Data = fmt.Sprintf("family: %s, type: %s, flags: %s, protocol: %s", saFamily, sockType, sockFlags, sockProtocol)
		}

	case "bind":
		if argNum == 5 {
			source := safeString(args[4])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}

			sockFd := safeInt32(args[0])
			saFamily := getSocketFamily(safeInt32(args[1]))

			evData.Category = "network"
			evData.Operation = "bind"

			switch saFamily {
			case "AF_UNIX":
				path := safeString(args[2])

				socketData := m.getDataFromSockMap(evData.HostPID, sockFd)
				if socketData != "" {
					evData.Data = fmt.Sprintf("fd: %d, %s, path: %s", sockFd, socketData, path)
				} else {
					evData.Data = fmt.Sprintf("fd: %d, family: %s, path: %s", sockFd, saFamily, path)
				}
				evData.Resource = path
				evData.TempInt32 = sockFd

			case "AF_INET":
				addr := lib.Uint32ToIPv4(safeUint32(args[2]))
				port := safeUint32(args[3])

				socketData := m.getDataFromSockMap(evData.HostPID, sockFd)
				if socketData != "" {
					evData.Data = fmt.Sprintf("fd: %d, %s, addr: %s, port: %d", sockFd, socketData, addr, port)
				} else {
					evData.Data = fmt.Sprintf("fd: %d, family: %s, addr: %s, port: %d", sockFd, saFamily, addr, port)
				}
				evData.Resource = fmt.Sprintf("%s:%d", addr, port)
				evData.TempInt32 = sockFd

			case "AF_PACKET":
				etherType := getEthProtocol(safeInt32(args[2]))
				ifindex := safeUint32(args[3])
				ifname := lib.GetIfName(ifindex)

				socketData := m.getDataFromSockMap(evData.HostPID, sockFd)
				if socketData != "" {
					evData.Data = fmt.Sprintf("fd: %d, %s, ifindex: %d, ifname: %s", sockFd, socketData, ifindex, ifname)
				} else {
					evData.Data = fmt.Sprintf("fd: %d, family: %s, protocol: %s, ifindex: %d, ifname: %s", sockFd, saFamily, etherType, ifindex, ifname)
				}
				evData.TempInt32 = sockFd
			}
		}

	case "connect":
		if argNum == 5 {
			source := safeString(args[4])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}

			sockFd := safeInt32(args[0])
			saFamily := getSocketFamily(safeInt32(args[1]))

			evData.Category = "network"
			evData.Operation = "connect"

			switch saFamily {
			case "AF_UNIX":
				path := safeString(args[2])

				socketData := m.getDataFromSockMap(evData.HostPID, sockFd)
				if socketData != "" {
					evData.Data = fmt.Sprintf("fd: %d, %s, path: %s", sockFd, socketData, path)
				} else {
					evData.Data = fmt.Sprintf("fd: %d, family: %s, path: %s", sockFd, saFamily, path)
				}
				evData.Resource = path
				evData.TempInt32 = sockFd

			case "AF_INET":
				addr := lib.Uint32ToIPv4(safeUint32(args[2]))
				port := safeUint32(args[3])

				socketData := m.getDataFromSockMap(evData.HostPID, sockFd)
				if socketData != "" {
					evData.Data = fmt.Sprintf("fd: %d, %s, addr: %s, port: %d", sockFd, socketData, addr, port)
				} else {
					evData.Data = fmt.Sprintf("fd: %d, family: %s, addr: %s, port: %d", sockFd, saFamily, addr, port)
				}
				evData.Resource = fmt.Sprintf("%s:%d", addr, port)
				evData.TempInt32 = sockFd
			}
		}

	case "listen":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}

			sockFd := safeInt32(args[0])
			backlog := safeInt32(args[1])

			evData.Category = "network"
			evData.Operation = "listen"

			socketData := m.getDataFromSockMap(evData.HostPID, sockFd)
			if socketData != "" {
				evData.Data = fmt.Sprintf("fd: %d, %s, backlog: %d", sockFd, socketData, backlog)
				evData.Resource = extractAddrPortFromSockData(socketData)
			} else {
				evData.Data = fmt.Sprintf("fd: %d, backlog: %d", sockFd, backlog)
			}
		}

	case "accept":
		if argNum == 2 {
			source := safeString(args[1])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}

			sockFd := safeInt32(args[0])

			evData.Category = "network"
			evData.Operation = "accept"

			socketData := m.getDataFromSockMap(evData.HostPID, sockFd)
			if socketData != "" {
				evData.Data = fmt.Sprintf("fd: %d, %s", sockFd, socketData)
			} else {
				evData.Data = fmt.Sprintf("fd: %d", sockFd)
			}
		}

	case "accept4":
		if argNum == 3 {
			source := safeString(args[2])
			if source != "unknown" {
				evData.Source = source
				m.updatePathToPidMap(evData.HostPID, source)
			} else {
				evData.Source = m.getPathFromPidMap(evData.HostPID)
			}

			sockFd := safeInt32(args[0])
			flags := safeInt32(args[1])

			evData.Category = "network"
			evData.Operation = "accept"

			socketData := m.getDataFromSockMap(evData.HostPID, sockFd)
			if socketData != "" {
				evData.Data = fmt.Sprintf("fd: %d, %s, flags: %s", sockFd, socketData, getAccept4Flags(flags))
			} else {
				evData.Data = fmt.Sprintf("fd: %d, flags: %s", sockFd, getAccept4Flags(flags))
			}
		}

	// kretprobe on inet_csk_accept — patches the pending accept/accept4 ENTER entry
	// with peer (client) address. Emitted as EVENT_UNARY so it is not exported itself.
	case "kretprobe_inet_csk_accept":
		if argNum == 2 {
			peerIP := lib.Uint32ToIPv4(safeUint32(args[0]))
			peerPort := safeUint32(args[1])
			peer := fmt.Sprintf("%s:%d", peerIP, peerPort)

			// Patch accept ENTER entry if present
			key1 := int64(evData.HostTID)<<16 | sysAccept
			if origEvData, ok := m.getEventData(key1); ok {
				origEvData.Resource = peer
				origEvData.Data += fmt.Sprintf(", peer: %s", peer)
				m.setEventData(key1, origEvData)
			}

			// Patch accept4 ENTER entry if present
			key2 := int64(evData.HostTID)<<16 | sysAccept4
			if origEvData, ok := m.getEventData(key2); ok {
				origEvData.Resource = peer
				origEvData.Data += fmt.Sprintf(", peer: %s", peer)
				m.setEventData(key2, origEvData)
			}
		}
	}

	return nil
}

// extractSuspiciousEnv filters envp for security-relevant variables (LD_PRELOAD, etc.)
// that indicate shared library injection or audit hooking.
func extractSuspiciousEnv(envp []string) string {
	sensitiveKeys := []string{"LD_PRELOAD=", "LD_LIBRARY_PATH=", "LD_AUDIT="}
	var found []string
	for _, e := range envp {
		for _, key := range sensitiveKeys {
			if strings.HasPrefix(e, key) {
				found = append(found, e)
				break
			}
		}
	}
	return strings.Join(found, " ")
}

// extractAddrPortFromSockData parses a sockMap data string of the form
// "family: AF_INET, protocol: TCP, addr: 1.2.3.4, port: 8080" and returns "1.2.3.4:8080".
func extractAddrPortFromSockData(data string) string {
	var addr, port string
	for _, part := range strings.Split(data, ", ") {
		if strings.HasPrefix(part, "addr: ") {
			addr = strings.TrimPrefix(part, "addr: ")
		} else if strings.HasPrefix(part, "port: ") {
			port = strings.TrimPrefix(part, "port: ")
		}
	}
	if addr != "" && port != "" {
		return addr + ":" + port
	}
	return ""
}
