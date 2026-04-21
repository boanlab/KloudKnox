# Integrating KloudKnox Streams

KloudKnox exposes three server-streaming gRPC RPCs (`EventStream`, `AlertStream`, `LogStream`) on port `36890` per agent, or port `36900` when the [relay server](https://github.com/boanlab/kloudknox-relay-server) is deployed. This document shows how to route those streams into logging pipelines, SIEM platforms, metrics backends, and alerting systems.

For the wire-format message schema, see [../protobuf/README.md](../protobuf/README.md). For the CLI reference, see the [kloudknox-cli repo](https://github.com/boanlab/kloudknox-cli).

---

## Table of Contents

- [Stream Shape](#stream-shape)
- [Local Filtering with `jq`](#local-filtering-with-jq)
- [Routing to Logging Pipelines](#routing-to-logging-pipelines)
  - [Fluent Bit](#fluent-bit)
  - [Vector](#vector)
  - [Loki](#loki)
  - [Elasticsearch / OpenSearch](#elasticsearch--opensearch)
- [Alerting on `Block` Events](#alerting-on-block-events)
  - [Slack / Webhook](#slack--webhook)
  - [PagerDuty Events API](#pagerduty-events-api)
- [Metrics from the Stream](#metrics-from-the-stream)
- [Custom gRPC Consumer](#custom-grpc-consumer)
- [Aggregating Across Nodes](#aggregating-across-nodes)
- [Production Deployment Notes](#production-deployment-notes)

---

## Stream Shape

`kkctl stream <events|alerts|logs>` writes NDJSON to stdout — one JSON object per line — and reconnects automatically on transient failures. Example alert line (wrapped for readability):

```json
{
  "timestamp": 1744000000000000000,
  "PID": 12345,
  "eventName": "execve",
  "category": "Process",
  "operation": "Exec",
  "resource": "/bin/sleep",
  "podName": "demo",
  "namespaceName": "default",
  "policyName": "block-sleep",
  "policyAction": "Block"
}
```

All downstream recipes in this document assume you are piping from `kkctl stream ...` or reading its stdout from a sidecar container.

---

## Local Filtering with `jq`

The simplest integration is a shell pipe. `jq` selects, projects, and pretty-prints:

```bash
# Only Block alerts
kkctl stream alerts | jq 'select(.policyAction == "Block")'

# Compact one-liner per alert
kkctl stream alerts | \
  jq -c '{ts: .timestamp, pod: .podName, action: .policyAction, resource: .resource}'

# Count alerts per policy in a 1-minute window
timeout 60 kkctl stream alerts | \
  jq -r '.policyName' | sort | uniq -c | sort -rn
```

---

## Routing to Logging Pipelines

The recommended pattern is: **run `kkctl stream` as a long-running process, tee to a log file, and let a log shipper tail that file.** This decouples the shipper from KloudKnox restarts.

```bash
# Start a durable writer (systemd unit, supervisord, or a sidecar)
mkdir -p /var/log/kloudknox
kkctl stream alerts >> /var/log/kloudknox/alerts.ndjson
```

### Fluent Bit

```ini
[INPUT]
    Name        tail
    Path        /var/log/kloudknox/alerts.ndjson
    Parser      json
    Tag         kloudknox.alerts
    Refresh_Interval 5

[OUTPUT]
    Name        forward
    Match       kloudknox.*
    Host        fluentd.logging.svc.cluster.local
    Port        24224
```

### Vector

```toml
[sources.kloudknox_alerts]
type = "file"
include = ["/var/log/kloudknox/alerts.ndjson"]
read_from = "end"

[transforms.parse]
type = "remap"
inputs = ["kloudknox_alerts"]
source = '''
  . = parse_json!(.message)
'''

[sinks.loki]
type = "loki"
inputs = ["parse"]
endpoint = "http://loki:3100"
labels = { source = "kloudknox", stream = "alerts", pod = "{{ podName }}" }
encoding.codec = "json"
```

### Loki

Push directly from a shell loop when a log shipper is not available:

```bash
kkctl stream alerts | while read -r line; do
  ts=$(date +%s%N)
  curl -s -H "Content-Type: application/json" -XPOST \
    "http://loki:3100/loki/api/v1/push" \
    --data-binary @- <<EOF
{
  "streams": [{
    "stream": {"source": "kloudknox", "type": "alert"},
    "values": [["$ts", "$line"]]
  }]
}
EOF
done
```

### Elasticsearch / OpenSearch

Filebeat works out of the box against the file tail path:

```yaml
filebeat.inputs:
  - type: filestream
    id: kloudknox-alerts
    paths:
      - /var/log/kloudknox/alerts.ndjson
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true

output.elasticsearch:
  hosts: ["https://es:9200"]
  indices:
    - index: "kloudknox-alerts-%{+yyyy.MM.dd}"
      when.equals:
        category: "Process"
```

---

## Alerting on `Block` Events

### Slack / Webhook

Pipe the stream through a filter and `curl` to a webhook:

```bash
kkctl stream alerts | \
  jq -c --unbuffered 'select(.policyAction == "Block")' | \
  while read -r alert; do
    text=$(echo "$alert" | jq -r '"\(.podName): \(.policyName) blocked \(.resource)"')
    curl -s -X POST -H 'Content-Type: application/json' \
      -d "{\"text\": \"$text\"}" \
      "$SLACK_WEBHOOK_URL"
  done
```

Note the `--unbuffered` flag on `jq` — without it, messages buffer until jq's stdout buffer flushes.

### PagerDuty Events API

```bash
kkctl stream alerts | \
  jq -c --unbuffered 'select(.policyAction == "Block")' | \
  while read -r alert; do
    summary=$(echo "$alert" | jq -r '"\(.podName)/\(.resource)"')
    curl -s -X POST "https://events.pagerduty.com/v2/enqueue" \
      -H 'Content-Type: application/json' \
      -d "$(cat <<EOF
{
  "routing_key": "$PD_ROUTING_KEY",
  "event_action": "trigger",
  "dedup_key": "kloudknox-$summary",
  "payload": {
    "summary": "KloudKnox blocked $summary",
    "source": "$(hostname)",
    "severity": "warning",
    "custom_details": $alert
  }
}
EOF
)"
  done
```

---

## Metrics from the Stream

Derive counters by tailing the stream and incrementing labeled metrics. The following sidecar-style script exposes a `/metrics` endpoint scrapable by Prometheus:

```bash
#!/usr/bin/env bash
# kloudknox-exporter.sh — trivial Prometheus exposer
set -euo pipefail

STATE=/tmp/kloudknox-counters
trap 'rm -f $STATE' EXIT

kkctl stream alerts | while read -r line; do
  policy=$(echo "$line" | jq -r '.policyName // "unknown"')
  action=$(echo "$line" | jq -r '.policyAction // "unknown"')
  echo "$policy $action" >> "$STATE"
done &

# Serve /metrics
python3 -m http.server 9100 --bind 0.0.0.0 --directory /tmp &
# (In production, replace with a proper exporter; this is illustrative.)
```

For production use, consume the gRPC API directly from a Go exporter — see [Custom gRPC Consumer](#custom-grpc-consumer) below.

---

## Custom gRPC Consumer

Use the generated stubs in `protobuf/` to build a consumer in any gRPC-supported language. Go example:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"

    kk "github.com/boanlab/KloudKnox/protobuf"
)

func main() {
    conn, err := grpc.NewClient(
        "localhost:36890",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := kk.NewKloudKnoxClient(conn)
    stream, err := client.AlertStream(context.Background(), &kk.AlertFilter{
        NamespaceName: "production",
    })
    if err != nil {
        log.Fatal(err)
    }

    for {
        alert, err := stream.Recv()
        if err != nil {
            log.Printf("stream closed: %v", err)
            return
        }
        if alert.PolicyAction == "Block" {
            fmt.Printf("BLOCK %s/%s -> %s (policy=%s)\n",
                alert.NamespaceName, alert.PodName,
                alert.Resource, alert.PolicyName)
        }
    }
}
```

Python consumers can use `grpcio` with the same `.proto` file. Re-generate stubs with:

```bash
python -m grpc_tools.protoc \
  -I protobuf \
  --python_out=. --grpc_python_out=. \
  protobuf/kloudknox.proto
```

Filter semantics are identical to the CLI: empty fields match everything; `podName` and `containerName` are prefix-matched.

---

## Aggregating Across Nodes

Each KloudKnox agent exposes its own `:36890`. For cluster-wide consumption, deploy the [relay server](https://github.com/boanlab/kloudknox-relay-server) and point consumers at its single endpoint:

```bash
kubectl apply -f https://raw.githubusercontent.com/boanlab/kloudknox-relay-server/main/deployments/relay-server.yaml
kubectl port-forward -n kloudknox deployment/kloudknox-relay 36900:36900

kkctl stream alerts --server localhost:36900
```

The relay server uses the same gRPC schema as the agents, so every recipe in this document works unchanged against port `36900` instead of `36890`.

---

## Production Deployment Notes

- **Run the shipper under a supervisor.** `systemd`, `supervisord`, or a Kubernetes sidecar — anything that restarts the process on crash. `kkctl stream` reconnects automatically on gRPC failures but cannot survive a host-level kill.
- **Buffer between KloudKnox and the sink.** A file tail (`tee` or direct stdout redirect to a log file) gives the downstream shipper a durable buffer and decouples it from KloudKnox restarts.
- **Pre-filter at the agent.** Passing `--namespaceName`, `--category`, or other filter flags at `kkctl stream` time is cheaper than filtering at the sink, because the agent skips sending unmatched records.
- **Watch queue depth on the relay.** The relay server drops messages for slow consumers rather than blocking the fanout (see the [kloudknox-relay-server repo](https://github.com/boanlab/kloudknox-relay-server)). Tune `--eventQueueSize` / `--alertQueueSize` / `--logQueueSize` if bursts cause drops.
- **Redact before sharing.** Alerts include pod names, process paths, and network targets. Strip these or aggregate to counts before sending to third-party dashboards.

---

## See also

- [README.md](README.md) — quickstart
- [use-cases.md](use-cases.md) — policy recipes that generate the alerts consumed here
- [troubleshooting.md](troubleshooting.md) — what to check when streams are empty
- https://github.com/boanlab/kloudknox-relay-server — multi-node aggregation
- [../protobuf/README.md](../protobuf/README.md) — full message schema
