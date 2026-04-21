// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

#include "system_events.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#include "file_events.h"
#include "ipc_events.h"
#include "network_events.h"
#include "process_events.h"
