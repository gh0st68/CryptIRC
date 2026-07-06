//! sysstatus.rs — read-only host + process metrics for the admin "Server Status"
//! panel (CPU, memory, disk, and the RSS of both the web process and the irc-core
//! daemon). Everything is derived from /proc and statvfs by the WEB process — the
//! daemon is never contacted or modified, so surfacing these numbers never needs
//! an irc-core restart. All collectors degrade gracefully (Option/None) so a
//! missing or unreadable /proc file can never take the endpoint down.

use serde::Serialize;

#[derive(Serialize, Default)]
pub struct Cpu {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub cores: usize,
    /// Instantaneous busy% sampled over a short window (None if unreadable).
    pub usage_pct: Option<f64>,
}

#[derive(Serialize, Default)]
pub struct Memory {
    pub total_kb: u64,
    pub available_kb: u64,
    pub used_kb: u64,
    pub used_pct: f64,
}

#[derive(Serialize, Default)]
pub struct Disk {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub used_bytes: u64,
    pub used_pct: f64,
    /// The filesystem this measures (the data dir's mount).
    pub path: String,
}

#[derive(Serialize, Default)]
pub struct Proc {
    pub name: String,
    pub pid: Option<u32>,
    pub rss_kb: Option<u64>,
    pub running: bool,
    /// How long THIS process has been running (not host uptime). None if unknown.
    pub uptime_secs: Option<u64>,
}

#[derive(Serialize, Default)]
pub struct ServerStatus {
    pub cpu: Cpu,
    pub memory: Memory,
    pub disk: Disk,
    /// The CryptIRC web process (this process).
    pub web: Proc,
    /// The irc-core daemon (found by scanning /proc for its binary name).
    pub daemon: Proc,
    pub uptime_secs: u64,
    pub irc_connections: usize,
    pub version: &'static str,
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// /proc/loadavg → (1m, 5m, 15m).
fn loadavg() -> (f64, f64, f64) {
    if let Some(s) = read("/proc/loadavg") {
        let mut it = s.split_whitespace();
        let a = it.next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
        let b = it.next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
        let c = it.next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
        return (a, b, c);
    }
    (0.0, 0.0, 0.0)
}

fn cores() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Sum of all jiffies + idle jiffies from the aggregate `cpu` line of /proc/stat.
fn cpu_totals() -> Option<(u64, u64)> {
    let s = read("/proc/stat")?;
    let line = s.lines().find(|l| l.starts_with("cpu "))?;
    let vals: Vec<u64> = line.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    if vals.len() < 5 { return None; }
    let total: u64 = vals.iter().sum();
    // idle = idle(3) + iowait(4)
    let idle = vals[3] + vals[4];
    Some((total, idle))
}

/// Busy% over a short sampling window. Returns None if /proc/stat is unreadable.
async fn cpu_usage_pct() -> Option<f64> {
    let (t0, i0) = cpu_totals()?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (t1, i1) = cpu_totals()?;
    let dt = t1.saturating_sub(t0);
    let di = i1.saturating_sub(i0);
    if dt == 0 { return None; }
    let busy = dt.saturating_sub(di) as f64 / dt as f64 * 100.0;
    Some((busy.clamp(0.0, 100.0) * 10.0).round() / 10.0)
}

/// Parse a `Key:   <num> kB` value out of a /proc meminfo/status style file.
fn parse_kb(body: &str, key: &str) -> Option<u64> {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            return rest.split_whitespace().next().and_then(|x| x.parse().ok());
        }
    }
    None
}

fn memory() -> Memory {
    let mut m = Memory::default();
    if let Some(body) = read("/proc/meminfo") {
        let total = parse_kb(&body, "MemTotal:").unwrap_or(0);
        // MemAvailable is the kernel's own estimate of reclaimable+free — the right
        // "how much can actually be used" number (falls back to MemFree pre-3.14).
        let avail = parse_kb(&body, "MemAvailable:")
            .or_else(|| parse_kb(&body, "MemFree:"))
            .unwrap_or(0);
        m.total_kb = total;
        m.available_kb = avail;
        m.used_kb = total.saturating_sub(avail);
        m.used_pct = if total > 0 { (m.used_kb as f64 / total as f64 * 100.0 * 10.0).round() / 10.0 } else { 0.0 };
    }
    m
}

fn disk(data_dir: &str) -> Disk {
    let mut d = Disk { path: data_dir.to_string(), ..Default::default() };
    // Reuse the proven statvfs pattern (see upload.rs quota check).
    if let Ok(c_path) = std::ffi::CString::new(data_dir) {
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if rc == 0 {
            let frsize = stat.f_frsize as u64;
            let total = stat.f_blocks as u64 * frsize;
            // f_bavail = blocks free to an unprivileged user (excludes root-reserved).
            let free = stat.f_bavail as u64 * frsize;
            d.total_bytes = total;
            d.free_bytes = free;
            d.used_bytes = total.saturating_sub(free);
            d.used_pct = if total > 0 { (d.used_bytes as f64 / total as f64 * 100.0 * 10.0).round() / 10.0 } else { 0.0 };
        }
    }
    d
}

fn uptime_secs() -> u64 {
    read("/proc/uptime")
        .and_then(|s| s.split_whitespace().next().and_then(|x| x.parse::<f64>().ok()))
        .map(|f| f as u64)
        .unwrap_or(0)
}

fn rss_kb_of(pid: u32) -> Option<u64> {
    let body = read(&format!("/proc/{}/status", pid))?;
    parse_kb(&body, "VmRSS:")
}

/// Clock ticks per second (usually 100). Used to convert /proc starttime jiffies.
fn clk_tck() -> u64 {
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 { t as u64 } else { 100 }
}

/// Seconds THIS pid has been running = host_uptime − (starttime_ticks / CLK_TCK).
/// /proc/<pid>/stat field 22 is starttime. comm (field 2) can contain spaces and
/// parens, so we split AFTER the last ')': the remaining tokens begin at field 3,
/// which makes starttime the token at index 19 (field 22 = field 3 + 19).
fn proc_uptime_secs(pid: u32, host_uptime: u64, tck: u64) -> Option<u64> {
    let stat = read(&format!("/proc/{}/stat", pid))?;
    let after = &stat[stat.rfind(')')? + 1..];
    let starttime: u64 = after.split_whitespace().nth(19)?.parse().ok()?;
    let secs_since_boot = starttime / tck.max(1);
    Some(host_uptime.saturating_sub(secs_since_boot))
}

/// This (web) process.
fn web_proc() -> Proc {
    let pid = std::process::id();
    Proc { name: "cryptirc (web)".into(), pid: Some(pid), rss_kb: rss_kb_of(pid), running: true, uptime_secs: None }
}

/// Find the irc-core daemon by scanning /proc for a process whose comm is
/// `irc_core` (the daemon binary name — see src/bin/irc_core.rs). Both processes
/// run as the same user, so its /proc entry is readable without privileges.
fn daemon_proc() -> Proc {
    let mut p = Proc { name: "irc-core (daemon)".into(), ..Default::default() };
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let fname = e.file_name();
            let Some(name) = fname.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else { continue };  // numeric dirs only
            if let Some(comm) = read(&format!("/proc/{}/comm", pid)) {
                if comm.trim() == "irc_core" {
                    p.pid = Some(pid);
                    p.rss_kb = rss_kb_of(pid);
                    p.running = true;
                    break;
                }
            }
        }
    }
    p
}

/// Collect a full snapshot. Async only because CPU% needs a short sampling window;
/// every other read is instant and infallible-by-default.
pub async fn collect(data_dir: &str, irc_connections: usize) -> ServerStatus {
    let (load1, load5, load15) = loadavg();
    let usage_pct = cpu_usage_pct().await;
    let host_uptime = uptime_secs();
    let tck = clk_tck();
    // Per-process uptimes computed from each pid's /proc starttime vs host uptime.
    let mut web = web_proc();
    if let Some(pid) = web.pid { web.uptime_secs = proc_uptime_secs(pid, host_uptime, tck); }
    let mut daemon = daemon_proc();
    if let Some(pid) = daemon.pid { daemon.uptime_secs = proc_uptime_secs(pid, host_uptime, tck); }
    ServerStatus {
        cpu: Cpu { load1, load5, load15, cores: cores(), usage_pct },
        memory: memory(),
        disk: disk(data_dir),
        web,
        daemon,
        uptime_secs: host_uptime,
        irc_connections,
        version: env!("CARGO_PKG_VERSION"),
    }
}
