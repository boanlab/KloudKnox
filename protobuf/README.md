# protobuf

Protobuf definitions and generated Go stubs for the KloudKnox gRPC service. The generated source files are committed alongside the `.proto` file and are imported directly by the KloudKnox daemon, relay server, and any gRPC client.

For consuming these streams with `kkctl`, see the [kloudknox-cli repo](https://github.com/boanlab/kloudknox-cli). For the end-to-end streaming walkthrough, see [../getting-started/README.md](../getting-started/README.md).

## Service Definition

```protobuf
service KloudKnox {
  rpc EventStream(EventFilter) returns (stream Event);
  rpc AlertStream(AlertFilter) returns (stream Alert);
  rpc LogStream(LogFilter)    returns (stream Log);
}
```

All three RPCs are **server-streaming**: the client sends one filter message and receives a continuous stream of records until the connection is closed.

## Messages

### Event

A raw system event captured by the eBPF monitor.

| Field | Type | Description |
|---|---|---|
| `Timestamp` | uint64 | Nanoseconds since epoch |
| `CPUID` | uint32 | CPU on which the event occurred |
| `SeqNum` | uint32 | Monotonic per-CPU sequence number |
| `HostPPID / HostPID / HostTID` | int32 | Host-level process identifiers (outside the container namespace) |
| `PPID / PID / TID` | int32 | Container-namespace process identifiers |
| `UID / GID` | uint32 | User and group identifiers |
| `EventID` | int32 | Numeric syscall identifier |
| `EventName` | string | Syscall name (e.g., `open`, `connect`) |
| `RetVal` | int32 | Raw return value |
| `RetCode` | string | Human-readable return code (e.g., `SUCCESS`, `EPERM`) |
| `Source` | string | Origin subsystem (e.g., `container`) |
| `Category` | string | Activity category (e.g., `File`, `Network`, `Process`) |
| `Operation` | string | Specific operation (e.g., `Read`, `Write`, `Connect`) |
| `Resource` | string | Target resource — file path, network address, etc. |
| `Data` | string | Additional context in `key=value,...` format |
| `NodeName` | string | Kubernetes node name |
| `NamespaceName` | string | Kubernetes namespace |
| `PodName` | string | Pod name |
| `ContainerName` | string | Container name |
| `Labels` | string | Pod labels serialized as `key=value,...` pairs |

### EventFilter

Selects which events are delivered on an `EventStream`. Empty fields match all records. `PodName` and `ContainerName` are matched by prefix; all other fields require an exact match.

### Alert

An `Event` that matched an active enforcement policy. Carries all `Event` fields plus two additional fields:

| Field | Type | Description |
|---|---|---|
| `PolicyName` | string | Name of the policy that triggered the alert |
| `PolicyAction` | string | Action taken: `Audit` or `Block` |

### AlertFilter

Identical matching rules to `EventFilter`.

### Log

A structured log entry emitted by the KloudKnox daemon.

| Field | Type | Description |
|---|---|---|
| `Timestamp` | uint64 | Nanoseconds since epoch |
| `Level` | string | Severity: `debug`, `info`, `warn`, or `error` |
| `Message` | string | Log message text |

### LogFilter

Selects which log entries are delivered on a `LogStream`. Set `Level` to a specific severity to receive only entries at that level; leave it empty to receive all entries.

## Generated Files

| File | Description |
|---|---|
| `kloudknox.proto` | Source Protobuf definition |
| `kloudknox.pb.go` | Generated message types |
| `kloudknox_grpc.pb.go` | Generated gRPC client and server interfaces |

Do **not** edit the generated `.pb.go` files by hand — run `make` to regenerate them from the `.proto` source.

## Regenerating Go Code

```bash
make
```

The Makefile installs `protoc`, `protoc-gen-go`, and `protoc-gen-go-grpc` automatically if they are not present, then regenerates the Go source files.

```bash
make clean   # remove generated files
```

## Import Path

```go
import "github.com/boanlab/KloudKnox/protobuf"
```

## Quick Client Example

```go
conn, _ := grpc.NewClient("localhost:36890", grpc.WithTransportCredentials(insecure.NewCredentials()))
client := protobuf.NewKloudKnoxClient(conn)

// Stream all policy alerts from a specific namespace
stream, _ := client.AlertStream(ctx, &protobuf.AlertFilter{
    NamespaceName: "default",
})
for {
    alert, err := stream.Recv()
    if err != nil {
        break
    }
    fmt.Printf("[%s] %s blocked by %s\n", alert.ContainerName, alert.Resource, alert.PolicyName)
}
```

## License

Apache License 2.0 — see the [LICENSE](../LICENSE) file for details.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
