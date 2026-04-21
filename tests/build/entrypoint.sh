#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University
#
# Default entrypoint: become PID 1 that just blocks. Pod specs override this
# via spec.containers[*].command for pods that need a listener (e.g.
# /usr/local/bin/kk-http-server 80). Keeping PID 1 as a single process is
# what lets narrow Allow+whitelist policies stay clean — no background
# daemons firing denials into the alerts stream.

exec /usr/bin/sleep infinity
