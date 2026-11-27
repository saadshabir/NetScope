use netscope::analysis::anomaly::{AlertKind, AnomalyDetector, AnomalySaturation};
use netscope::config::{AnomalyConfig, PortScanConfig, SynFloodConfig};
use netscope::flow::{Endpoint, FlowProtocol};
use std::net::{IpAddr, Ipv4Addr};

const KEYS_PER_BURST: u16 = 4096;
const SWEEP_SECS: u32 = 30;

fn main() {
    let mut args = std::env::args().skip(1);
    let period = match args.next().as_deref() {
        Some("burst") => 60,
        Some("idle") => 600,
        _ => panic!("expected a workload of burst or idle"),
    };
    let cycles: u32 = args.next().expect("expected cycle count").parse().unwrap();
    let mut detector = AnomalyDetector::new(AnomalyConfig {
        enabled: true,
        syn_flood: SynFloodConfig {
            enabled: true,
            window_secs: 5.0,
            syn_threshold: 1,
            unique_src_threshold: 1,
            cooldown_secs: 3.0,
        },
        port_scan: PortScanConfig {
            enabled: true,
            window_secs: 5.0,
            unique_ports_threshold: 1,
            unique_hosts_threshold: 0,
            cooldown_secs: 3.0,
        },
    });
    let mut syn_alerts = 0;
    let mut scan_alerts = 0;
    for cycle in 0..cycles {
        let start = u64::from(cycle) * u64::from(period);
        detector.advance_time(start as f64);
        for key in 1..=KEYS_PER_BURST {
            let src = Endpoint {
                ip: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + u32::from(key))),
                port: 40_000,
            };
            let dst = Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                port: key,
            };
            for alert in detector
                .observe(start as f64 + 1.0, FlowProtocol::Tcp, src, dst, true, false)
                .unwrap()
            {
                match alert.kind {
                    AlertKind::SynFlood => syn_alerts += 1,
                    AlertKind::PortScan => scan_alerts += 1,
                }
            }
        }
        // Advance the capture watermark with frames that carry no detector evidence.
        for offset in (SWEEP_SECS..=period).step_by(SWEEP_SECS as usize) {
            detector.advance_time((start + u64::from(offset)) as f64);
        }
    }
    let observations = u64::from(cycles) * u64::from(KEYS_PER_BURST);
    assert_eq!(syn_alerts, observations);
    assert_eq!(scan_alerts, observations);
    assert_eq!(detector.saturation(), AnomalySaturation::default());

    #[cfg(target_os = "linux")]
    println!(
        "{observations} {syn_alerts} {scan_alerts} {}",
        peak_rss_bytes()
    );
    #[cfg(not(target_os = "linux"))]
    println!("{observations} {syn_alerts} {scan_alerts}");
}

#[cfg(target_os = "linux")]
fn peak_rss_bytes() -> u64 {
    // VmHWM tracks this executable's address space after exec.
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    let peak_rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.split_whitespace().next())
        .expect("/proc/self/status contains VmHWM")
        .parse::<u64>()
        .expect("VmHWM is a number in KiB");
    peak_rss_kib * 1024
}
