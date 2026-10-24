//! The Linux readings of the host probe, as functions of text: the first line of
//! `/proc/stat` for the CPU counters and `MemTotal` and `MemAvailable` of `/proc/meminfo`.
//! The probe reads the files into one reused buffer and hands the text to these functions,
//! so the tests feed captured text.

use super::CpuTimes;

/// The CPU counters of the aggregate line of `/proc/stat` (`cpu  user nice system idle iowait
/// irq softirq steal guest guest_nice`, in clock ticks). The guest columns are left out: the
/// kernel counts guest time in `user` and `nice` already. A kernel that stops after `idle`
/// (before 2.5.41) reads with the missing columns as zero.
pub(super) fn parse_cpu(text: &str) -> Option<CpuTimes> {
    let line = text.lines().next()?;
    let mut fields = line.split_ascii_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let mut counters = [0_u64; 8];
    let mut read = 0;
    for (slot, field) in counters.iter_mut().zip(fields) {
        *slot = field.parse().ok()?;
        read += 1;
    }
    if read < 4 {
        return None;
    }
    let [user, nice, system, idle, iowait, irq, softirq, steal] = counters;
    let idle_all = idle.saturating_add(iowait);
    let busy = [user, nice, system, irq, softirq, steal]
        .into_iter()
        .fold(0_u64, u64::saturating_add);
    Some(CpuTimes {
        busy,
        total: busy.saturating_add(idle_all),
    })
}

/// `MemTotal` and `MemAvailable` of `/proc/meminfo` in bytes; a missing or malformed line reads
/// as `None` (`MemAvailable` is missing before Linux 3.14).
pub(super) fn parse_memory(text: &str) -> (Option<u64>, Option<u64>) {
    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let slot = match name {
            "MemTotal" => &mut total,
            "MemAvailable" => &mut available,
            _ => continue,
        };
        *slot = kibibytes(rest);
        if total.is_some() && available.is_some() {
            break;
        }
    }
    (total, available)
}

/// A value of `/proc/meminfo` (`  16384 kB`) in bytes.
fn kibibytes(text: &str) -> Option<u64> {
    let mut fields = text.split_ascii_whitespace();
    let count: u64 = fields.next()?.parse().ok()?;
    match fields.next() {
        Some("kB") => count.checked_mul(1024),
        None => Some(count),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "\
cpu  4705 150 1120 16250 520 30 45 10 0 0
cpu0 1175 37 280 4062 130 7 11 2 0 0
cpu1 1176 38 281 4063 130 8 11 3 0 0
intr 1462898 0 10 0
ctxt 2154217
btime 1704067200
";

    const MEMINFO: &str = "\
MemTotal:       16384000 kB
MemFree:         1200000 kB
MemAvailable:    9830400 kB
Buffers:          300000 kB
Cached:          6000000 kB
";

    #[test]
    fn the_aggregate_line_gives_busy_and_total_ticks() {
        // busy = user + nice + system + irq + softirq + steal; idle = idle + iowait.
        assert_eq!(
            parse_cpu(STAT),
            Some(CpuTimes {
                busy: 4705 + 150 + 1120 + 30 + 45 + 10,
                total: 4705 + 150 + 1120 + 30 + 45 + 10 + 16250 + 520,
            })
        );
    }

    #[test]
    fn an_old_kernel_with_four_columns_and_garbage_read_as_far_as_they_can() {
        assert_eq!(
            parse_cpu("cpu 10 0 5 85\n"),
            Some(CpuTimes {
                busy: 15,
                total: 100
            })
        );
        assert_eq!(parse_cpu("cpu 10 0 5\n"), None, "idle is missing");
        assert_eq!(
            parse_cpu("cpu0 10 0 5 85\n"),
            None,
            "not the aggregate line"
        );
        assert_eq!(parse_cpu("cpu 10 x 5 85\n"), None);
        assert_eq!(parse_cpu(""), None);
    }

    #[test]
    fn the_memory_lines_are_kibibytes() {
        assert_eq!(
            parse_memory(MEMINFO),
            (Some(16_384_000 * 1024), Some(9_830_400 * 1024))
        );
    }

    #[test]
    fn a_missing_or_malformed_memory_line_is_absent() {
        let old = "MemTotal:  2048 kB\nMemFree:  100 kB\n";
        assert_eq!(parse_memory(old), (Some(2048 * 1024), None));
        assert_eq!(
            parse_memory("MemTotal: lots kB\nMemAvailable: 5 MB\n"),
            (None, None)
        );
        assert_eq!(parse_memory(""), (None, None));
        // No unit: bytes, as a file system other than procfs might print.
        assert_eq!(parse_memory("MemTotal: 4096\n").0, Some(4096));
    }
}
