//! Core capture engine: opens a pcap handle and yields raw packet data.

use pcap::{Active, Capture, Device, Offline};
use std::fmt;
use std::path::Path;

/// Errors from the capture engine.
#[derive(Debug)]
pub enum CaptureError {
    /// Failed to find a suitable network device.
    NoDevice(String),
    /// pcap error.
    Pcap(pcap::Error),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::NoDevice(msg) => write!(f, "no capture device: {}", msg),
            CaptureError::Pcap(e) => write!(f, "pcap error: {}", e),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<pcap::Error> for CaptureError {
    fn from(e: pcap::Error) -> Self {
        CaptureError::Pcap(e)
    }
}

/// Configuration for opening a capture.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub promiscuous: bool,
    pub snaplen: i32,
    pub timeout_ms: i32,
    pub buffer_size_mb: Option<u32>,
    pub immediate_mode: bool,
    pub filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            interface: None,
            promiscuous: true,
            snaplen: 65535,
            timeout_ms: 100,
            buffer_size_mb: None,
            immediate_mode: false,
            filter: None,
        }
    }
}

/// List all available network interfaces.
pub fn list_interfaces() -> Result<Vec<Device>, CaptureError> {
    Device::list().map_err(CaptureError::Pcap)
}

/// Open a live packet capture with the given configuration.
/// Returns an active `pcap::Capture` handle.
pub fn open_capture(config: &CaptureConfig) -> Result<Capture<Active>, CaptureError> {
    // Select the device
    let device = match &config.interface {
        Some(name) => {
            let devices = Device::list().map_err(CaptureError::Pcap)?;
            devices
                .into_iter()
                .find(|d| d.name == *name)
                .ok_or_else(|| CaptureError::NoDevice(format!("interface '{}' not found", name)))?
        }
        None => Device::lookup()
            .map_err(CaptureError::Pcap)?
            .ok_or_else(|| CaptureError::NoDevice("no default device found".into()))?,
    };

    let device_name = device.name.clone();

    // Open the capture handle
    let mut cap = Capture::from_device(device)
        .map_err(CaptureError::Pcap)?
        .promisc(config.promiscuous)
        .snaplen(config.snaplen)
        .timeout(config.timeout_ms);

    // The supported libpcap versions expose this API through pcap.
    cap = cap.immediate_mode(config.immediate_mode);

    if let Some(buffer_size_mb) = config.buffer_size_mb {
        let snaplen = config.snaplen.max(0);
        let buffer_size_bytes = buffer_size_mb
            .max(1)
            .saturating_mul(1024)
            .saturating_mul(1024)
            .min(i32::MAX as u32) as i32;
        let buffer_size_bytes = buffer_size_bytes.max(snaplen);
        cap = cap.buffer_size(buffer_size_bytes);
    }

    let mut cap = cap.open().map_err(CaptureError::Pcap)?;

    // Apply BPF filter if specified
    if let Some(filter) = &config.filter {
        cap.filter(filter, true).map_err(CaptureError::Pcap)?;
    }

    // Linux's packet-buffer timeout does not guarantee that an idle read
    // returns. Nonblocking reads let the caller check shutdown and timers.
    #[cfg(target_os = "linux")]
    let cap = cap.setnonblock().map_err(CaptureError::Pcap)?;

    tracing::info!(
        interface = %device_name,
        promiscuous = config.promiscuous,
        snaplen = config.snaplen,
        timeout_ms = config.timeout_ms,
        immediate_mode = config.immediate_mode,
        buffer_size_mb = config.buffer_size_mb,
        filter = config.filter.as_deref().unwrap_or("none"),
        "capture started"
    );

    Ok(cap)
}

/// Open an offline pcap file and optionally apply a BPF filter.
pub fn open_offline(path: &Path, filter: Option<&str>) -> Result<Capture<Offline>, CaptureError> {
    let mut cap = Capture::from_file(path).map_err(CaptureError::Pcap)?;

    if let Some(filter) = filter {
        cap.filter(filter, true).map_err(CaptureError::Pcap)?;
    }

    tracing::info!(
        pcap = %path.display(),
        filter = filter.unwrap_or("none"),
        "offline capture opened"
    );

    Ok(cap)
}
