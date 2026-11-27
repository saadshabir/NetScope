use netscope::{capture, config};
use std::time::{Duration, Instant};

const LIVE_PCAP_STATS_POLL_INTERVAL_MS: u64 = 250;

/// List available network interfaces and print them.
pub(crate) fn list_interfaces() {
    match capture::engine::list_interfaces() {
        Ok(devices) => {
            println!("Available network interfaces:");
            println!("{:<20} {:<20} Addresses", "Name", "Description");
            println!("{}", "-".repeat(70));
            for device in &devices {
                let desc = device.desc.as_deref().unwrap_or("");
                let addrs: Vec<String> = device
                    .addresses
                    .iter()
                    .map(|a| format!("{}", a.addr))
                    .collect();
                println!("{:<20} {:<20} {}", device.name, desc, addrs.join(", "));
            }
            if devices.is_empty() {
                println!("  (no interfaces found — try running with sudo)");
            }
        }
        Err(e) => {
            eprintln!("error listing interfaces: {}", e);
            eprintln!("hint: try running with sudo");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureMode {
    Live,
    Offline,
}

pub(crate) enum CaptureSource {
    Live(pcap::Capture<pcap::Active>),
    Offline(pcap::Capture<pcap::Offline>),
}

pub(crate) enum CaptureRead<'a> {
    Packet(pcap::Packet<'a>),
    Idle,
    Eof,
}

impl CaptureSource {
    pub(crate) fn mode(&self) -> CaptureMode {
        match self {
            CaptureSource::Live(_) => CaptureMode::Live,
            CaptureSource::Offline(_) => CaptureMode::Offline,
        }
    }

    pub(crate) fn get_datalink(&self) -> pcap::Linktype {
        match self {
            CaptureSource::Live(cap) => cap.get_datalink(),
            CaptureSource::Offline(cap) => cap.get_datalink(),
        }
    }

    pub(crate) fn savefile<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
        exclusive: bool,
    ) -> Result<pcap::Savefile, pcap::Error> {
        #[cfg(unix)]
        {
            use std::os::fd::IntoRawFd;
            let path = path.as_ref();
            let file = if exclusive {
                netscope::output_file::create_new(path)
            } else {
                netscope::output_file::create(path)
            }
            .map_err(|err| {
                pcap::Error::PcapError(format!("cannot open {}: {err}", path.display()))
            })?;
            let fd = file.into_raw_fd();
            // SAFETY: ownership of the checked, writable file descriptor is
            // transferred to libpcap; no Rust File can close or reuse it.
            let result = unsafe {
                match self {
                    CaptureSource::Live(cap) => cap.savefile_raw_fd(fd),
                    CaptureSource::Offline(cap) => cap.savefile_raw_fd(fd),
                }
            };
            // fdopen leaves ownership with the caller if it fails.
            if matches!(result, Err(pcap::Error::InvalidRawFd)) {
                // SAFETY: fdopen failed, so this descriptor is still ours.
                unsafe { libc::close(fd) };
            }
            result
        }
        #[cfg(not(unix))]
        {
            let _ = exclusive;
            match self {
                CaptureSource::Live(cap) => cap.savefile(path),
                CaptureSource::Offline(cap) => cap.savefile(path),
            }
        }
    }

    pub(crate) fn next_packet(&mut self) -> Result<CaptureRead<'_>, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => match cap.next_packet() {
                Ok(packet) => Ok(CaptureRead::Packet(packet)),
                Err(pcap::Error::TimeoutExpired) => {
                    // Linux live handles are nonblocking; avoid spinning when
                    // no packet is available while keeping shutdown responsive.
                    #[cfg(target_os = "linux")]
                    std::thread::sleep(Duration::from_millis(1));
                    Ok(CaptureRead::Idle)
                }
                Err(err) => Err(err),
            },
            CaptureSource::Offline(cap) => match cap.next_packet() {
                Ok(packet) => Ok(CaptureRead::Packet(packet)),
                Err(pcap::Error::NoMorePackets) => Ok(CaptureRead::Eof),
                Err(err) => Err(err),
            },
        }
    }

    pub(crate) fn stats(&mut self) -> Result<Option<pcap::Stat>, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => cap.stats().map(Some),
            CaptureSource::Offline(_) => Ok(None),
        }
    }

    pub(crate) fn open(config: &config::CaptureConfig) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(path) = config.read_pcap.as_deref() {
            Ok(Self::Offline(capture::engine::open_offline(
                path,
                config.filter.as_deref(),
            )?))
        } else {
            let capture_config = capture::engine::CaptureConfig {
                interface: config.interface.clone(),
                promiscuous: config.promiscuous,
                snaplen: config.snaplen,
                timeout_ms: config.timeout_ms,
                buffer_size_mb: config.buffer_size_mb,
                immediate_mode: config.immediate_mode,
                filter: config.filter.clone(),
            };
            Ok(Self::Live(capture::engine::open_capture(&capture_config)?))
        }
    }

    pub(crate) fn start_live_stats_poll(&self) -> Option<Instant> {
        (self.mode() == CaptureMode::Live).then(|| {
            Instant::now()
                .checked_sub(Duration::from_millis(LIVE_PCAP_STATS_POLL_INTERVAL_MS))
                .unwrap_or_else(Instant::now)
        })
    }

    pub(crate) fn poll_live_pcap_stats(
        &mut self,
        last_poll: &mut Option<Instant>,
    ) -> Option<(u64, u64)> {
        let last_poll = last_poll.as_mut()?;
        let now = Instant::now();
        if (now.duration_since(*last_poll).as_millis() as u64) < LIVE_PCAP_STATS_POLL_INTERVAL_MS {
            return None;
        }
        *last_poll = now;

        match self.stats() {
            Ok(Some(stats)) => Some((stats.dropped as u64, stats.if_dropped as u64)),
            Ok(None) => None,
            Err(e) => {
                tracing::debug!(error = %e, "failed to read live pcap stats");
                None
            }
        }
    }
}

pub(crate) fn packet_timestamp(packet: &pcap::Packet<'_>) -> f64 {
    packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0
}
