#!/usr/bin/env bash
# Prints the CPU time and the resident set of a server process on this (Linux) host, for the
# runs where the load comes from another host and the harness cannot sample the server by pid
# (M17). Run it on the server host right before and right after a load run; the CPU seconds of
# the run are the difference.
#
# Usage: server-cpu.sh PID
# Output: "<unix time> <cpu seconds> <rss MiB>", one line.
set -eu
pid="${1:?usage: server-cpu.sh PID}"
[ -r "/proc/$pid/stat" ] || { echo "no such process: $pid" >&2; exit 2; }
ticks=$(getconf CLK_TCK)
# Fields 14 and 15 of /proc/PID/stat are utime and stime; the command name (field 2) may hold
# spaces, so cut after the closing parenthesis.
cpu=$(sed 's/^.*) //' "/proc/$pid/stat" | awk -v t="$ticks" '{ printf "%.2f", ($12 + $13) / t }')
rss=$(awk '$1 == "VmRSS:" { printf "%.1f", $2 / 1024 }' "/proc/$pid/status")
echo "$(date +%s.%N) $cpu $rss"
