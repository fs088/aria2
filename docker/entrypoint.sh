#!/bin/sh
# Container bootstrap for aria2.
#
# Deliberately dumb: it reads NO environment variables and adds NO download
# options. It only guarantees aria2c's input-file (the session) exists before
# handing over control, because aria2c opens input-file unconditionally at
# startup and aborts if it is missing -- which is exactly what happens when a
# host directory is bind-mounted over /config and has no session file yet.
#
# All real configuration still comes from the config file plus CLI arguments:
# the fixed --conf-path lives here so it survives argument overrides, and "$@"
# (the CMD, or flags passed to `docker run`) is appended and takes precedence.

# touch creates the file if absent and never truncates an existing session.
touch /config/aria2.session 2>/dev/null || true

exec /usr/bin/aria2c --conf-path=/config/aria2.conf "$@"
