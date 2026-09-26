mod cli;

use netscope::run_summary::{self, RunAccounting, RunSummary};
use netscope::{
    analysis, capture, config, display, flow, memory, metrics, pipeline, protocol, web,
};
use netscope::{build_packet_data, maybe_analyze_anomaly, sinks};

use clap::Parser;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn main() {
    metrics::initialize();

    let args = cli::Cli::parse();

    if let Some(count) = args.synthetic_flows {
        run_synthetic_flow_memory(count);
        return;
    }

    // Initialize tracing/logging
    let log_level = match args.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Handle --list-interfaces
    if args.list_interfaces {
        list_interfaces();
        return;
    }

    let config = match load_config(&args) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    };

    // Set up Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::SeqCst);
        eprintln!("\nInterrupt received, stopping capture...");
    })
    .expect("failed to set Ctrl-C handler");

    // Run the capture loop
    if let Err(e) = run_capture(&config, &running) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run_synthetic_flow_memory(count: usize) {
    let start = Instant::now();
    let mut tracker = flow::FlowTracker::new(0.0, count.saturating_add(1), false, false, false);

    if !tracker.is_scale_mode() {
        eprintln!("error: synthetic flow benchmark requires scale mode");
        std::process::exit(1);
    }

    tracker.insert_synthetic_ipv4_flows(count);
    let elapsed = start.elapsed().as_secs_f64();
    let rss_kb = memory::current_rss_kb().unwrap_or(0);

    println!("Synthetic flow benchmark complete.");
    println!("  Flows inserted:     {}", tracker.len());
    println!("  Mode:               scale");
    println!("  Elapsed:            {:.3}s", elapsed);
    if rss_kb > 0 {
        println!("  RSS (estimated):    {:.2} MB", rss_kb as f64 / 1024.0);
        if rss_kb > 500 * 1024 {
            eprintln!("  Budget check:       FAIL (> 500 MB)");
            std::process::exit(2);
        } else {
            println!("  Budget check:       PASS (< 500 MB)");
        }
    } else {
        println!("  RSS (estimated):    unavailable");
    }
}

/// List available network interfaces and print them.
fn list_interfaces() {
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
enum CaptureMode {
    Live,
    Offline,
}

enum CaptureSource {
    Live(pcap::Capture<pcap::Active>),
    Offline(pcap::Capture<pcap::Offline>),
}

enum CaptureRead<'a> {
    Packet(pcap::Packet<'a>),
    Idle,
    Eof,
}

impl CaptureSource {
    fn mode(&self) -> CaptureMode {
        match self {
            CaptureSource::Live(_) => CaptureMode::Live,
            CaptureSource::Offline(_) => CaptureMode::Offline,
        }
    }

    fn get_datalink(&self) -> pcap::Linktype {
        match self {
            CaptureSource::Live(cap) => cap.get_datalink(),
            CaptureSource::Offline(cap) => cap.get_datalink(),
        }
    }

    fn savefile<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
    ) -> Result<pcap::Savefile, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => cap.savefile(path),
            CaptureSource::Offline(cap) => cap.savefile(path),
        }
    }

    fn next_packet(&mut self) -> Result<CaptureRead<'_>, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => match cap.next_packet() {
                Ok(packet) => Ok(CaptureRead::Packet(packet)),
                Err(pcap::Error::TimeoutExpired) => Ok(CaptureRead::Idle),
                Err(err) => Err(err),
            },
            CaptureSource::Offline(cap) => match cap.next_packet() {
                Ok(packet) => Ok(CaptureRead::Packet(packet)),
                Err(pcap::Error::NoMorePackets) => Ok(CaptureRead::Eof),
                Err(err) => Err(err),
            },
        }
    }

    fn stats(&mut self) -> Result<Option<pcap::Stat>, pcap::Error> {
        match self {
            CaptureSource::Live(cap) => cap.stats().map(Some),
            CaptureSource::Offline(_) => Ok(None),
        }
    }
}

/// Main capture loop: open capture, read packets, parse, and display.
fn run_capture(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    config.validate()?;
    let run_start = Instant::now();
    let mut cap = open_capture_source(config)?;
    let link_type = protocol::LinkType::from_pcap_value(cap.get_datalink().0);
    let capture_mode = cap.mode();
    let rotation_policy = PcapRotationPolicy::from_output(&config.output);
    let mut savefile = match &config.output.write_pcap {
        Some(path) => Some(RotatingSavefile::open(
            &mut cap,
            path.as_path(),
            rotation_policy,
        )?),
        None => None,
    };
    // Start web dashboard if enabled.
    let web_handle = start_web_dashboard(config)?;

    print_capture_intro(config, capture_mode)?;
    println!("Datalink: {}", link_type);

    let mut accounting = RunAccounting::default();
    let processing_result = if config.pipeline.enabled {
        run_capture_pipeline(
            config,
            running,
            link_type,
            &mut cap,
            savefile.as_mut(),
            web_handle.as_ref(),
            &mut accounting,
        )
    } else {
        run_capture_inline(
            config,
            running,
            link_type,
            &mut cap,
            savefile.as_mut(),
            web_handle.as_ref(),
            &mut accounting,
        )
    };

    match cap.stats() {
        Ok(Some(stats)) => {
            accounting.kernel_drops = Some(stats.dropped as u64);
            accounting.interface_drops = Some(stats.if_dropped as u64);
        }
        Ok(None) => {}
        Err(err) => tracing::debug!(error = %err, "failed to read final pcap stats"),
    }

    let output_errors = accounting.output_errors.clone();
    let status = if processing_result.is_err() || !output_errors.is_empty() {
        "failed"
    } else if !running.load(Ordering::SeqCst) {
        "interrupted"
    } else {
        "success"
    };
    let mode = if config.pipeline.enabled {
        "pipeline"
    } else {
        "inline"
    };
    let source = run_summary::source_description(
        config.capture.read_pcap.as_deref(),
        config.capture.interface.as_deref(),
    );
    let effective_config = run_summary::effective_config(run_summary::EffectiveConfigInput {
        capture: &config.capture,
        flow: &config.flow,
        packet_limit: config.run.count,
        analysis: &config.analysis,
        output: &config.output,
        stats: &config.stats,
        web: &config.web,
        pipeline_enabled: config.pipeline.enabled,
        requested_workers: config.pipeline.workers,
        pipeline_channel_capacity: config.pipeline.channel_capacity,
        link_type,
    });
    let summary = RunSummary::new(
        mode,
        source,
        run_start.elapsed().as_secs_f64(),
        status,
        processing_result.as_ref().err().map(ToString::to_string),
        effective_config,
        accounting.clone(),
    );

    print_run_summary(&summary);
    if let Some(path) = config.output.summary_json.as_deref() {
        run_summary::write_json(path, &summary).map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("failed to write run summary '{}': {}", path.display(), err),
            )
        })?;
    }

    println!("{}", "=".repeat(50));

    processing_result?;
    if !summary.output_errors.is_empty() {
        return Err(std::io::Error::other(format!(
            "{} output error(s) occurred; see the run summary",
            summary.output_errors.len()
        ))
        .into());
    }
    Ok(())
}

fn print_run_summary(summary: &RunSummary) {
    println!();
    println!("{}", "=".repeat(50));
    if summary.mode == "pipeline" {
        println!(
            "Capture complete (pipeline mode; status: {}).",
            summary.status
        );
    } else {
        println!("Capture complete (status: {}).", summary.status);
    }
    println!("  Packets captured:  {}", summary.frames_read);
    println!("  Input wire bytes:   {}", summary.input_wire_bytes);
    println!("  Packets parsed:     {}", summary.packets_parsed);
    println!(
        "  Transport headers:  {}",
        summary.packets_with_transport_header
    );
    println!(
        "  Malformed/unsupported: {}",
        summary.malformed_or_unsupported_packets
    );
    if let Some(dispatched) = summary.dispatched_frames {
        println!("  Dispatched frames:  {}", dispatched);
        println!(
            "  Dispatch drops:    {}",
            summary.dispatch_drops.unwrap_or(0)
        );
        println!(
            "  Worker processed:   {}",
            summary.worker_processed_frames.unwrap_or(0)
        );
        println!(
            "  Worker failures:    {}",
            summary.worker_failures.unwrap_or(0)
        );
    } else {
        println!(
            "  Parse errors:      {}",
            summary.malformed_or_unsupported_packets
        );
        println!(
            "  Success rate:       {:.1}%",
            if summary.frames_read > 0 {
                (summary.frames_read - summary.malformed_or_unsupported_packets) as f64
                    / summary.frames_read as f64
                    * 100.0
            } else {
                0.0
            }
        );
    }
    println!("  Flows created:      {}", summary.flows_created);
    println!("  Flows expired:      {}", summary.flows_expired);
    println!("  Flows evicted:      {}", summary.flows_evicted);
    println!("  Alerts emitted:     {}", summary.alerts_emitted);
    println!("  Elapsed:            {:.3}s", summary.elapsed_wall_seconds);
    println!(
        "  Kernel/interface drops: {}/{}",
        summary
            .kernel_drops
            .map_or_else(|| "unavailable".into(), |value| value.to_string()),
        summary
            .interface_drops
            .map_or_else(|| "unavailable".into(), |value| value.to_string())
    );
    if !summary.output_errors.is_empty() {
        println!("  Output errors:      {}", summary.output_errors.len());
        for error in &summary.output_errors {
            println!("    - {error}");
        }
    }
    if let Some(error) = &summary.run_error {
        println!("  Run error:          {error}");
    }
}

fn open_capture_source(
    config: &RuntimeConfig,
) -> Result<CaptureSource, Box<dyn std::error::Error>> {
    if let Some(path) = config.capture.read_pcap.as_deref() {
        Ok(CaptureSource::Offline(capture::engine::open_offline(
            path,
            config.capture.filter.as_deref(),
        )?))
    } else {
        let capture_config = capture::engine::CaptureConfig {
            interface: config.capture.interface.clone(),
            promiscuous: config.capture.promiscuous,
            snaplen: config.capture.snaplen,
            timeout_ms: config.capture.timeout_ms,
            buffer_size_mb: config.capture.buffer_size_mb,
            immediate_mode: config.capture.immediate_mode,
            filter: config.capture.filter.clone(),
        };
        Ok(CaptureSource::Live(capture::engine::open_capture(
            &capture_config,
        )?))
    }
}

fn start_web_dashboard(
    config: &RuntimeConfig,
) -> Result<Option<web::server::WebHandle>, Box<dyn std::error::Error>> {
    if !config.web.enabled {
        return Ok(None);
    }

    let tls = if config.web.tls.enabled {
        Some(web::server::WebServerTlsConfig {
            cert_path: config
                .web
                .tls
                .cert_path
                .clone()
                .expect("web tls cert_path validated"),
            key_path: config
                .web
                .tls
                .key_path
                .clone()
                .expect("web tls key_path validated"),
        })
    } else {
        None
    };

    let auth = if config.web.auth.enabled {
        let password = config
            .web
            .auth
            .resolve_password()
            .map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid web dashboard config: {}", err),
                )
            })?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid web dashboard config: web auth enabled but no password resolved",
                )
            })?;

        Some(web::server::WebServerAuthConfig {
            username: config.web.auth.username.clone(),
            password,
        })
    } else {
        None
    };

    if auth.is_some() && tls.is_none() {
        tracing::warn!("web auth is enabled without TLS; credentials will be sent in cleartext");
    }

    let server_config = web::server::WebServerConfig {
        bind: config.web.bind.clone(),
        port: config.web.port,
        tick_ms: config.web.tick_ms,
        packet_buffer: config.web.packet_buffer,
        tls,
        auth,
    };
    let handle = web::server::start(server_config)
        .map_err(|err| std::io::Error::other(format!("error starting web dashboard: {}", err)))?;

    Ok(Some(handle))
}

fn print_capture_intro(
    config: &RuntimeConfig,
    capture_mode: CaptureMode,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("NetScope v{}", env!("CARGO_PKG_VERSION"));
    match capture_mode {
        CaptureMode::Live => {
            let interface_name = config.capture.interface.as_deref().unwrap_or("(default)");
            println!("Capturing on interface: {}", interface_name);
        }
        CaptureMode::Offline => match config.capture.read_pcap.as_ref() {
            Some(path) => println!("Reading packets from pcap: {}", path.display()),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "configuration error: offline capture requires capture.read_pcap path",
                )
                .into());
            }
        },
    }
    if let Some(filter) = &config.capture.filter {
        println!("Filter: {}", filter);
    }
    if config.run.count > 0 {
        println!("Processing {} packets...", config.run.count);
    } else {
        match capture_mode {
            CaptureMode::Live => println!("Capturing packets (Ctrl-C to stop)..."),
            CaptureMode::Offline => println!("Processing packets until EOF..."),
        }
    }
    Ok(())
}

const SAVEFILE_FLUSH_INTERVAL_PACKETS: u64 = 1024;
const LIVE_PCAP_STATS_POLL_INTERVAL_MS: u64 = 250;
const SAVEFILE_GLOBAL_HEADER_BYTES: u64 = 24;
const SAVEFILE_PACKET_RECORD_BYTES: u64 = 16;

#[derive(Debug, Clone, Copy)]
struct PcapRotationPolicy {
    max_bytes: u64,
    max_files: usize,
}

impl PcapRotationPolicy {
    fn from_output(output: &config::OutputConfig) -> Option<Self> {
        if output.write_pcap_rotate_mb == 0 && output.write_pcap_max_files == 0 {
            return None;
        }
        Some(PcapRotationPolicy {
            max_bytes: output.write_pcap_rotate_mb.saturating_mul(1024 * 1024),
            max_files: output.write_pcap_max_files,
        })
    }
}

struct RotatingSavefile {
    base_path: PathBuf,
    rotation: Option<PcapRotationPolicy>,
    current_segment: u64,
    current_bytes: u64,
    rotate_pending: bool,
    segment_paths: VecDeque<PathBuf>,
    savefile: pcap::Savefile,
}

impl RotatingSavefile {
    fn open(
        cap: &mut CaptureSource,
        base_path: &Path,
        rotation: Option<PcapRotationPolicy>,
    ) -> Result<Self, pcap::Error> {
        if let Some(rotation) = rotation {
            let existing_segments = Self::collect_existing_segments(base_path);
            let first_segment = existing_segments
                .last()
                .map(|(segment, _)| segment.saturating_add(1))
                .unwrap_or(1);
            let path = Self::segment_path(base_path, first_segment);
            let savefile = cap.savefile(&path)?;
            let mut segment_paths: VecDeque<PathBuf> = existing_segments
                .into_iter()
                .map(|(_, path)| path)
                .collect();
            segment_paths.push_back(path);

            let mut writer = Self {
                base_path: base_path.to_path_buf(),
                rotation: Some(rotation),
                current_segment: first_segment,
                current_bytes: SAVEFILE_GLOBAL_HEADER_BYTES,
                rotate_pending: false,
                segment_paths,
                savefile,
            };
            writer.prune_old_segments(rotation.max_files);
            Ok(writer)
        } else {
            let savefile = cap.savefile(base_path)?;
            Ok(Self {
                base_path: base_path.to_path_buf(),
                rotation,
                current_segment: 0,
                current_bytes: 0,
                rotate_pending: false,
                segment_paths: VecDeque::new(),
                savefile,
            })
        }
    }

    fn write_packet(
        &mut self,
        packet: &pcap::Packet<'_>,
        packet_count: u64,
    ) -> Result<(), pcap::Error> {
        self.savefile.write(packet);
        if packet_count.is_multiple_of(SAVEFILE_FLUSH_INTERVAL_PACKETS) {
            self.savefile.flush()?;
        }

        if let Some(rotation) = self.rotation {
            self.current_bytes = self.current_bytes.saturating_add(
                SAVEFILE_PACKET_RECORD_BYTES.saturating_add(packet.data.len() as u64),
            );
            if self.current_bytes >= rotation.max_bytes {
                self.rotate_pending = true;
            }
        }

        Ok(())
    }

    fn rotate_if_needed(&mut self, cap: &mut CaptureSource) -> Result<(), pcap::Error> {
        let Some(rotation) = self.rotation else {
            return Ok(());
        };
        if !self.rotate_pending {
            return Ok(());
        }

        self.savefile.flush()?;
        self.current_segment = self.current_segment.saturating_add(1);
        let next_path = Self::segment_path(&self.base_path, self.current_segment);
        self.savefile = cap.savefile(&next_path)?;
        self.current_bytes = SAVEFILE_GLOBAL_HEADER_BYTES;
        self.rotate_pending = false;
        self.segment_paths.push_back(next_path);
        self.prune_old_segments(rotation.max_files);

        Ok(())
    }

    fn flush(&mut self) -> Result<(), pcap::Error> {
        self.savefile.flush()
    }

    fn segment_path(base_path: &Path, segment: u64) -> PathBuf {
        let parent = base_path.parent().unwrap_or_else(|| Path::new(""));
        let stem = base_path
            .file_stem()
            .or_else(|| base_path.file_name())
            .unwrap_or_else(|| OsStr::new("capture"));

        let mut filename = OsString::from(stem);
        filename.push(format!(".{:06}", segment));
        if let Some(ext) = base_path.extension() {
            filename.push(".");
            filename.push(ext);
        }

        parent.join(filename)
    }

    fn collect_existing_segments(base_path: &Path) -> Vec<(u64, PathBuf)> {
        let parent = base_path.parent().unwrap_or_else(|| Path::new("."));
        let mut segments = Vec::new();

        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(
                    path = %parent.display(),
                    error = %err,
                    "failed to read pcap rotation directory"
                );
                return segments;
            }
        };

        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|file_type| file_type.is_file()) {
                continue;
            }

            let path = entry.path();
            if let Some(segment) = Self::parse_segment_index(base_path, &path) {
                segments.push((segment, path));
            }
        }

        segments.sort_unstable_by_key(|(segment, _)| *segment);
        segments
    }

    fn parse_segment_index(base_path: &Path, path: &Path) -> Option<u64> {
        let file_name = path.file_name()?.to_string_lossy();
        let stem = base_path
            .file_stem()
            .or_else(|| base_path.file_name())
            .unwrap_or_else(|| OsStr::new("capture"))
            .to_string_lossy();

        let with_stem_prefix = format!("{}.", stem);

        let index_str = if let Some(ext) = base_path.extension() {
            let ext_suffix = format!(".{}", ext.to_string_lossy());
            let without_ext = file_name.strip_suffix(&ext_suffix)?;
            without_ext.strip_prefix(&with_stem_prefix)?
        } else {
            file_name.strip_prefix(&with_stem_prefix)?
        };

        index_str.parse().ok()
    }

    fn prune_old_segments(&mut self, max_files: usize) {
        while self.segment_paths.len() > max_files {
            if let Some(old_path) = self.segment_paths.pop_front()
                && let Err(err) = std::fs::remove_file(&old_path)
            {
                tracing::warn!(
                    path = %old_path.display(),
                    error = %err,
                    "failed to remove old rotated pcap file"
                );
            }
        }
    }
}

fn write_packet_to_savefile(
    savefile: &mut Option<&mut RotatingSavefile>,
    packet: &pcap::Packet<'_>,
    packet_count: u64,
) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.write_packet(packet, packet_count)?;
    }
    Ok(())
}

fn maybe_rotate_savefile(
    cap: &mut CaptureSource,
    savefile: &mut Option<&mut RotatingSavefile>,
) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.rotate_if_needed(cap)?;
    }
    Ok(())
}

fn flush_savefile(savefile: &mut Option<&mut RotatingSavefile>) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.flush()?;
    }
    Ok(())
}

struct PipelinePacketDispatcher<'a> {
    capture_mode: CaptureMode,
    link_type: protocol::LinkType,
    senders: &'a [crossbeam_channel::Sender<pipeline::OwnedPacket>],
    buffer_pool: &'a pipeline::PacketBufPool,
    stats: &'a pipeline::PipelineStats,
}

impl PipelinePacketDispatcher<'_> {
    fn write_and_dispatch(
        &self,
        packet: &pcap::Packet<'_>,
        packet_count: u64,
        savefile: &mut Option<&mut RotatingSavefile>,
        accounting: &mut RunAccounting,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Err(err) = write_packet_to_savefile(savefile, packet, packet_count) {
            tracing::error!(error = %err, "pcap write error");
            accounting
                .output_errors
                .push(format!("pcap write error: {err}"));
            self.record_dispatch_drop(accounting);
            return Err(Box::new(err));
        }

        let timestamp =
            packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        let wire_len = packet.header.len as u64;
        let shard = pipeline::router::shard_for_packet_with_linktype(
            packet.data,
            self.senders.len(),
            self.link_type,
        );
        let mut buf = self.buffer_pool.acquire();
        buf.extend_from_slice(packet.data);
        let owned = pipeline::OwnedPacket {
            id: packet_count,
            ts: timestamp,
            wire_len,
            data: buf,
        };

        match self.capture_mode {
            CaptureMode::Offline => {
                if let Err(err) = self.senders[shard].send(owned) {
                    let dropped = err.0;
                    self.buffer_pool.release(dropped.data);
                    self.record_dispatch_drop(accounting);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!(
                            "pipeline worker {} stopped before offline packet {} was dispatched",
                            shard, packet_count
                        ),
                    )
                    .into());
                }
                accounting.dispatched_frames =
                    Some(accounting.dispatched_frames.unwrap_or(0).saturating_add(1));
            }
            CaptureMode::Live => match self.senders[shard].try_send(owned) {
                Ok(_) => {
                    accounting.dispatched_frames =
                        Some(accounting.dispatched_frames.unwrap_or(0).saturating_add(1));
                }
                Err(crossbeam_channel::TrySendError::Full(dropped)) => {
                    self.record_dispatch_drop(accounting);
                    self.buffer_pool.release(dropped.data);
                    tracing::trace!(shard, "worker channel full, dropping live packet");
                }
                Err(crossbeam_channel::TrySendError::Disconnected(dropped)) => {
                    self.record_dispatch_drop(accounting);
                    self.buffer_pool.release(dropped.data);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!("pipeline worker {} stopped during live capture", shard),
                    )
                    .into());
                }
            },
        }

        Ok(())
    }

    fn record_dispatch_drop(&self, accounting: &mut RunAccounting) {
        self.stats.record_dispatch_drop();
        accounting.dispatch_drops = Some(accounting.dispatch_drops.unwrap_or(0).saturating_add(1));
    }
}

#[derive(Debug, Default)]
struct InlineKernelStats {
    dropped_total: u64,
    if_dropped_total: u64,
    dropped_interval_stats: u64,
    if_dropped_interval_stats: u64,
    dropped_interval_web: u64,
    if_dropped_interval_web: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct PcapDropSnapshot {
    dropped_total: u64,
    if_dropped_total: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct PcapDropDelta {
    dropped: u64,
    if_dropped: u64,
}

impl InlineKernelStats {
    fn update_totals(&mut self, dropped_total: u64, if_dropped_total: u64) {
        let dropped_delta = if self.initialized {
            dropped_total.saturating_sub(self.dropped_total)
        } else {
            0
        };
        let if_dropped_delta = if self.initialized {
            if_dropped_total.saturating_sub(self.if_dropped_total)
        } else {
            0
        };
        self.dropped_total = dropped_total;
        self.if_dropped_total = if_dropped_total;
        self.dropped_interval_stats = self.dropped_interval_stats.saturating_add(dropped_delta);
        self.if_dropped_interval_stats = self
            .if_dropped_interval_stats
            .saturating_add(if_dropped_delta);
        self.dropped_interval_web = self.dropped_interval_web.saturating_add(dropped_delta);
        self.if_dropped_interval_web = self
            .if_dropped_interval_web
            .saturating_add(if_dropped_delta);
        self.initialized = true;
    }

    fn take_stats_interval(&mut self) -> (u64, u64) {
        let dropped = self.dropped_interval_stats;
        let if_dropped = self.if_dropped_interval_stats;
        self.dropped_interval_stats = 0;
        self.if_dropped_interval_stats = 0;
        (dropped, if_dropped)
    }

    fn take_web_interval(&mut self) -> (u64, u64) {
        let dropped = self.dropped_interval_web;
        let if_dropped = self.if_dropped_interval_web;
        self.dropped_interval_web = 0;
        self.if_dropped_interval_web = 0;
        (dropped, if_dropped)
    }
}

fn maybe_poll_live_pcap_stats(
    cap: &mut CaptureSource,
    last_poll: &mut Instant,
) -> Option<(u64, u64)> {
    let now = Instant::now();
    if (now.duration_since(*last_poll).as_millis() as u64) < LIVE_PCAP_STATS_POLL_INTERVAL_MS {
        return None;
    }
    *last_poll = now;

    match cap.stats() {
        Ok(Some(stats)) => Some((stats.dropped as u64, stats.if_dropped as u64)),
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(error = %e, "failed to read live pcap stats");
            None
        }
    }
}

#[inline]
fn unix_secs_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn flush_expired_flows(
    sinks: &mut sinks::ExpiredFlowSinks,
    events: &mut Vec<flow::ExpiredFlowEvent>,
) -> Result<(), std::io::Error> {
    if events.is_empty() {
        return Ok(());
    }
    let drained = std::mem::take(events);
    sinks.write_events(&drained)
}

fn flush_expired_flows_accounted(
    output_sinks: &mut sinks::OutputSinks,
    events: &mut Vec<flow::ExpiredFlowEvent>,
    accounting: &mut RunAccounting,
) -> Result<(), Box<dyn std::error::Error>> {
    match flush_expired_flows(&mut output_sinks.expired_flows, events) {
        Ok(()) => Ok(()),
        Err(err) => {
            accounting.output_errors.extend(output_sinks.take_errors());
            accounting.output_errors.push(err.to_string());
            Err(Box::new(err))
        }
    }
}

fn sync_flow_accounting(accounting: &mut RunAccounting, tracker: &flow::FlowTracker) {
    let stats = tracker.stats();
    accounting.flows_created = stats.created;
    accounting.flows_expired = stats.expired;
    accounting.flows_evicted = stats.evicted;
}

/// Original single-threaded capture loop (no pipeline).
fn run_capture_inline(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
    link_type: protocol::LinkType,
    cap: &mut CaptureSource,
    mut savefile: Option<&mut RotatingSavefile>,
    web_handle: Option<&web::server::WebHandle>,
    accounting: &mut RunAccounting,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();

    let mut packet_count: u64 = 0;
    let mut flow_tracker = flow::FlowTracker::new(
        config.flow.timeout_secs,
        config.flow.max_flows,
        config.analysis.rtt,
        config.analysis.retrans,
        config.analysis.out_of_order,
    );
    let mut output_sinks = sinks::OutputSinks::open(
        config.analysis.alerts_jsonl.as_deref(),
        config.output.expired_flows_jsonl.as_deref(),
        config.output.expired_flows_csv.as_deref(),
    );
    let emit_expired_flows = output_sinks.emit_expired_flows();
    let mut anomaly_detector =
        analysis::anomaly::AnomalyDetector::new(config.analysis.anomalies.clone());
    let mut expired_flow_events: Vec<flow::ExpiredFlowEvent> = Vec::new();
    let mut last_expire_check_ts: f64 = 0.0;

    let mut stats_last = Instant::now();
    let mut stats_bytes: u64 = 0;
    let mut stats_packets: u64 = 0;
    let mut kernel_stats = InlineKernelStats::default();
    let mut live_stats_poll_last = if cap.mode() == CaptureMode::Live {
        Some(
            Instant::now()
                .checked_sub(Duration::from_millis(LIVE_PCAP_STATS_POLL_INTERVAL_MS))
                .unwrap_or_else(Instant::now),
        )
    } else {
        None
    };

    // Web dashboard tick state
    let mut web_tick_last = Instant::now();
    let mut web_tick_bytes: u64 = 0;
    let mut web_tick_packets: u64 = 0;
    let mut web_frame_seq: u64 = 0;

    let capture_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        while running.load(Ordering::SeqCst) {
            // Check packet count limit
            if config.run.count > 0 && packet_count >= config.run.count {
                break;
            }

            if let Err(err) = maybe_rotate_savefile(cap, &mut savefile) {
                tracing::error!(error = %err, "pcap rotate error");
                return Err(Box::new(err));
            }

            // Read next packet
            let packet = match cap.next_packet() {
                Ok(CaptureRead::Packet(packet)) => Some(packet),
                Ok(CaptureRead::Idle) => None,
                Ok(CaptureRead::Eof) => break,
                Err(e) => {
                    tracing::error!(error = %e, "capture error");
                    return Err(Box::new(e));
                }
            };

            if let Some(packet) = packet {
                packet_count += 1;
                accounting.frames_read = packet_count;

                let timestamp =
                    packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
                let raw_data = packet.data;
                let wire_len = packet.header.len as u64;
                accounting.input_wire_bytes = accounting.input_wire_bytes.saturating_add(wire_len);

                if let Err(err) = write_packet_to_savefile(&mut savefile, &packet, packet_count) {
                    tracing::error!(error = %err, "pcap write error");
                    accounting
                        .output_errors
                        .push(format!("pcap write error: {err}"));
                    return Err(Box::new(err));
                }

                // Parse the packet
                match protocol::parse_packet_with_linktype(raw_data, link_type) {
                    Ok(parsed) => {
                        accounting.packets_parsed = accounting.packets_parsed.saturating_add(1);
                        if parsed.transport.is_some() {
                            accounting.packets_with_transport_header =
                                accounting.packets_with_transport_header.saturating_add(1);
                        }
                        if parsed.transport_parse_error.is_some() || parsed.unsupported {
                            accounting.malformed_or_unsupported_packets = accounting
                                .malformed_or_unsupported_packets
                                .saturating_add(1);
                        }
                        if let Some(err) = parsed.transport_parse_error.as_ref() {
                            tracing::debug!(error = %err, "malformed transport header on packet #{}", packet_count);
                        }
                        if config.analysis.anomalies.enabled {
                            let alerts =
                                maybe_analyze_anomaly(&mut anomaly_detector, timestamp, &parsed)?;
                            accounting.alerts_emitted = accounting
                                .alerts_emitted
                                .saturating_add(alerts.len() as u64);
                            for alert in &alerts {
                                if let Err(err) = output_sinks.write_alert(
                                    alert.ts,
                                    alert.kind.as_str(),
                                    &alert.description,
                                ) {
                                    accounting.output_errors.extend(output_sinks.take_errors());
                                    accounting.output_errors.push(err.to_string());
                                    return Err(Box::new(err));
                                }
                                println!("[alert] {}", alert.description);
                                // Forward alerts to web dashboard
                                if let Some(handle) = web_handle
                                    && handle
                                        .event_tx
                                        .try_send(web::messages::CaptureEvent::Alert(
                                            web::messages::AlertMsg {
                                                ts: alert.ts,
                                                kind: alert.kind.as_str().to_string(),
                                                description: alert.description.clone(),
                                            },
                                        ))
                                        .is_err()
                                {
                                    tracing::trace!("web event channel full, dropping alert");
                                }
                            }
                        }
                        flow_tracker.observe(timestamp, wire_len, &parsed);
                        sync_flow_accounting(accounting, &flow_tracker);

                        // Send packet samples to web dashboard.
                        if let Some(handle) = web_handle
                            && config.web.sample_rate > 0
                            && packet_count.is_multiple_of(config.web.sample_rate)
                        {
                            let (sample, stored) = build_packet_data(
                                packet_count,
                                timestamp,
                                raw_data,
                                &parsed,
                                config.web.payload_bytes,
                            );
                            if handle
                                .event_tx
                                .try_send(web::messages::CaptureEvent::Packet(sample))
                                .is_err()
                            {
                                tracing::trace!("web event channel full, dropping packet sample");
                            }
                            if handle
                                .event_tx
                                .try_send(web::messages::CaptureEvent::PacketStored(stored))
                                .is_err()
                            {
                                tracing::trace!("web event channel full, dropping stored packet");
                            }
                        }

                        if config.output.hex_dump || config.verbose_level >= 2 {
                            display::print_packet_detail(
                                packet_count,
                                timestamp,
                                raw_data,
                                &parsed,
                            );
                        } else if !config.output.quiet {
                            display::print_packet_summary(packet_count, timestamp, &parsed);
                        }
                    }
                    Err(e) => {
                        accounting.malformed_or_unsupported_packets = accounting
                            .malformed_or_unsupported_packets
                            .saturating_add(1);
                        display::print_parse_error(packet_count, timestamp, raw_data.len(), &e);
                        tracing::debug!(error = %e, "parse error on packet #{}", packet_count);
                    }
                }

                stats_bytes += wire_len;
                stats_packets += 1;
                web_tick_bytes += wire_len;
                web_tick_packets += 1;

                if timestamp < last_expire_check_ts {
                    last_expire_check_ts = timestamp;
                } else if (timestamp - last_expire_check_ts) >= 1.0 {
                    last_expire_check_ts = timestamp;
                    if emit_expired_flows {
                        flow_tracker.maybe_expire_collect(timestamp, &mut expired_flow_events);
                        flush_expired_flows_accounted(
                            &mut output_sinks,
                            &mut expired_flow_events,
                            accounting,
                        )?;
                    } else {
                        flow_tracker.maybe_expire(timestamp);
                    }
                }
            } else {
                let now_ts = unix_secs_now();
                if now_ts < last_expire_check_ts {
                    last_expire_check_ts = now_ts;
                } else if (now_ts - last_expire_check_ts) >= 1.0 {
                    last_expire_check_ts = now_ts;
                    if emit_expired_flows {
                        flow_tracker.maybe_expire_collect(now_ts, &mut expired_flow_events);
                        flush_expired_flows_accounted(
                            &mut output_sinks,
                            &mut expired_flow_events,
                            accounting,
                        )?;
                    } else {
                        flow_tracker.maybe_expire(now_ts);
                    }
                }
            }

            if let Some(last_poll) = live_stats_poll_last.as_mut()
                && let Some((dropped_total, if_dropped_total)) =
                    maybe_poll_live_pcap_stats(cap, last_poll)
            {
                kernel_stats.update_totals(dropped_total, if_dropped_total);
            }

            // Stats printing
            let now = Instant::now();
            if config.stats.enabled
                && now.duration_since(stats_last).as_millis() as u64 >= config.stats.interval_ms
            {
                let elapsed = now.duration_since(stats_last).as_secs_f64().max(0.001);
                let mbps = stats_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                let pps = stats_packets as f64 / elapsed;
                let active_flows = flow_tracker.len();
                let (kernel_drops, kernel_if_drops) = kernel_stats.take_stats_interval();
                let kernel_snapshot = PcapDropSnapshot {
                    dropped_total: kernel_stats.dropped_total,
                    if_dropped_total: kernel_stats.if_dropped_total,
                };
                println!(
                    "[stats] {:.2} Mbps | {:.0} pps | {} flows | kdrop={} (total={}) ifdrop={} (total={})",
                    mbps,
                    pps,
                    active_flows,
                    kernel_drops,
                    kernel_snapshot.dropped_total,
                    kernel_if_drops,
                    kernel_snapshot.if_dropped_total
                );

                if config.stats.top_flows > 0 {
                    let top = flow_tracker.top_flows_by_delta(config.stats.top_flows as usize);
                    for (rank, entry) in top.iter().enumerate() {
                        let mbps = entry.delta_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                        println!("  {}. {} {:.2} Mbps", rank + 1, entry.key, mbps);
                    }
                }

                stats_last = now;
                stats_bytes = 0;
                stats_packets = 0;
            }

            // Web dashboard tick
            if let Some(handle) = web_handle {
                let now = Instant::now();
                if now.duration_since(web_tick_last).as_millis() as u64 >= config.web.tick_ms {
                    let elapsed = now.duration_since(web_tick_last).as_secs_f64().max(0.001);
                    let mbps = web_tick_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                    let pps = web_tick_packets as f64 / elapsed;
                    let active_flows = flow_tracker.len();

                    let top_deltas = flow_tracker.top_flows_with_snapshot(config.web.top_n);
                    let top_flows: Vec<web::messages::FlowInfo> = top_deltas
                        .iter()
                        .map(|(delta, snap)| {
                            web::messages::FlowInfo::from_snapshot_delta(
                                snap,
                                delta.delta_bytes,
                                elapsed,
                            )
                        })
                        .collect();
                    let (kernel_drops, kernel_if_drops) = kernel_stats.take_web_interval();
                    let kernel_snapshot = PcapDropSnapshot {
                        dropped_total: kernel_stats.dropped_total,
                        if_dropped_total: kernel_stats.if_dropped_total,
                    };
                    let kernel_delta = PcapDropDelta {
                        dropped: kernel_drops,
                        if_dropped: kernel_if_drops,
                    };

                    metrics::observe_tick(
                        web_tick_bytes,
                        web_tick_packets,
                        active_flows,
                        0,
                        kernel_delta.dropped,
                        kernel_delta.if_dropped,
                    );

                    let tick = web::messages::StatsTick {
                        ts: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs_f64(),
                        frame_seq: web_frame_seq,
                        server_ts: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64,
                        interval_ms: config.web.tick_ms,
                        bytes: web_tick_bytes,
                        packets: web_tick_packets,
                        mbps,
                        pps,
                        active_flows,
                        dispatch_drops: 0,
                        dispatch_drops_total: 0,
                        kernel_drops: kernel_delta.dropped,
                        kernel_drops_total: kernel_snapshot.dropped_total,
                        kernel_if_drops: kernel_delta.if_dropped,
                        kernel_if_drops_total: kernel_snapshot.if_dropped_total,
                        top_flows,
                    };

                    if handle
                        .event_tx
                        .try_send(web::messages::CaptureEvent::Tick(tick))
                        .is_err()
                    {
                        tracing::trace!("web event channel full, dropping stats tick");
                    }

                    web_frame_seq = web_frame_seq.wrapping_add(1);

                    web_tick_last = now;
                    web_tick_bytes = 0;
                    web_tick_packets = 0;
                }
            }
        }
        Ok(())
    })();

    let mut final_error = capture_result.err().map(|err| err.to_string());
    if let Err(err) =
        flush_expired_flows_accounted(&mut output_sinks, &mut expired_flow_events, accounting)
    {
        final_error.get_or_insert_with(|| err.to_string());
    }
    sync_flow_accounting(accounting, &flow_tracker);
    accounting.output_errors.extend(output_sinks.take_errors());

    if let Err(err) = flush_savefile(&mut savefile) {
        tracing::error!(error = %err, "pcap flush error");
        accounting
            .output_errors
            .push(format!("pcap flush error: {err}"));
        final_error.get_or_insert_with(|| err.to_string());
    }

    if config.output.export_json.is_some() || config.output.export_csv.is_some() {
        let snapshot = flow_tracker.snapshot();
        if let Some(path) = &config.output.export_json {
            if let Err(err) = flow::write_flow_json(path.as_ref(), &snapshot) {
                accounting.output_errors.push(format!(
                    "flow JSON export '{}' failed: {err}",
                    path.display()
                ));
                final_error.get_or_insert_with(|| err.to_string());
            } else {
                println!("  Flow export (JSON): {}", path.display());
            }
        }
        if let Some(path) = &config.output.export_csv {
            if let Err(err) = flow::write_flow_csv(path.as_ref(), &snapshot) {
                accounting.output_errors.push(format!(
                    "flow CSV export '{}' failed: {err}",
                    path.display()
                ));
                final_error.get_or_insert_with(|| err.to_string());
            } else {
                println!("  Flow export (CSV):  {}", path.display());
            }
        }
    }

    if let Some(err) = final_error {
        return Err(std::io::Error::other(err).into());
    }
    if !accounting.output_errors.is_empty() {
        return Err(std::io::Error::other(format!(
            "{} output error(s) occurred",
            accounting.output_errors.len()
        ))
        .into());
    }
    Ok(())
}

/// Sharded pipeline capture loop: the main thread only reads from pcap
/// and dispatches owned packet buffers to worker shards.
fn run_capture_pipeline(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
    link_type: protocol::LinkType,
    cap: &mut CaptureSource,
    mut savefile: Option<&mut RotatingSavefile>,
    web_handle: Option<&web::server::WebHandle>,
    accounting: &mut RunAccounting,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use the full snaplen as the pool buffer size so every captured packet
    // fits without reallocation. Fall back to 65535 if snaplen is 0 (unset).
    let packet_buf_size = match config.capture.snaplen {
        s if s > 0 => s as usize,
        _ => 65535,
    };
    let kernel_stats = Arc::new(pipeline::KernelPcapStats::new());

    let pipeline_cfg = pipeline::PipelineConfig {
        num_workers: config.pipeline.workers,
        channel_capacity: config.pipeline.channel_capacity,
        buffer_pool_capacity: config.pipeline.channel_capacity.saturating_mul(2).max(1),
        packet_buf_size,
        flow: config.flow.clone(),
        analysis: config.analysis.clone(),
        stats: config.stats.clone(),
        web: config.web.clone(),
        heavy_hitter_top_n: config.web.top_n.max(config.stats.top_flows as usize),
        alerts_jsonl: config.analysis.alerts_jsonl.clone(),
        expired_flows_jsonl: config.output.expired_flows_jsonl.clone(),
        expired_flows_csv: config.output.expired_flows_csv.clone(),
        kernel_stats: kernel_stats.clone(),
        link_type,
    };

    let mut pipe = pipeline::spawn(pipeline_cfg, running.clone(), web_handle)?;
    let num_workers = pipe.num_workers();
    accounting.worker_count = Some(num_workers);
    accounting.dispatched_frames = Some(0);
    accounting.dispatch_drops = Some(0);
    accounting.worker_processed_frames = Some(0);
    accounting.worker_failures = Some(0);
    let capture_mode = cap.mode();
    let dispatcher = PipelinePacketDispatcher {
        capture_mode,
        link_type,
        senders: &pipe.senders,
        buffer_pool: &pipe.buffer_pool,
        stats: &pipe.stats,
    };
    println!("Pipeline: {} worker shards", num_workers);
    println!();

    let mut packet_count: u64 = 0;
    let mut stats_last = Instant::now();
    let mut live_stats_poll_last = if cap.mode() == CaptureMode::Live {
        Some(
            Instant::now()
                .checked_sub(Duration::from_millis(LIVE_PCAP_STATS_POLL_INTERVAL_MS))
                .unwrap_or_else(Instant::now),
        )
    } else {
        None
    };

    let capture_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        while running.load(Ordering::SeqCst) {
            if config.run.count > 0 && packet_count >= config.run.count {
                break;
            }

            if let Err(err) = maybe_rotate_savefile(cap, &mut savefile) {
                tracing::error!(error = %err, "pcap rotate error");
                return Err(Box::new(err));
            }

            let packet = match cap.next_packet() {
                Ok(CaptureRead::Packet(packet)) => Some(packet),
                Ok(CaptureRead::Idle) => None,
                Ok(CaptureRead::Eof) => break,
                Err(e) => {
                    tracing::error!(error = %e, "capture error");
                    return Err(Box::new(e));
                }
            };

            if let Some(packet) = packet {
                packet_count += 1;
                accounting.frames_read = packet_count;

                let wire_len = packet.header.len as u64;
                accounting.input_wire_bytes = accounting.input_wire_bytes.saturating_add(wire_len);
                dispatcher.write_and_dispatch(&packet, packet_count, &mut savefile, accounting)?;
            }

            if let Some(last_poll) = live_stats_poll_last.as_mut()
                && let Some((dropped_total, if_dropped_total)) =
                    maybe_poll_live_pcap_stats(cap, last_poll)
            {
                kernel_stats.update_totals(dropped_total, if_dropped_total);
            }

            // CLI stats from aggregator
            let now = Instant::now();
            if config.stats.enabled
                && now.duration_since(stats_last).as_millis() as u64 >= config.stats.interval_ms
            {
                if let Some(tick) = pipe.aggregator.take_tick() {
                    println!(
                        "[stats] {:.2} Mbps | {:.0} pps | {} flows | drops={} (total={}) | kdrop={} (total={}) ifdrop={} (total={})",
                        tick.mbps,
                        tick.pps,
                        tick.active_flows,
                        tick.dispatch_drops,
                        tick.dispatch_drops_total,
                        tick.kernel_drops,
                        tick.kernel_drops_total,
                        tick.kernel_if_drops,
                        tick.kernel_if_drops_total
                    );
                    if config.stats.top_flows > 0 {
                        let elapsed = (tick.interval_ms as f64 / 1000.0).max(0.001);
                        for (rank, (delta, _snap)) in tick
                            .top_flows
                            .iter()
                            .enumerate()
                            .take(config.stats.top_flows as usize)
                        {
                            let mbps = delta.delta_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
                            println!("  {}. {} {:.2} Mbps", rank + 1, delta.key, mbps);
                        }
                    }
                }
                stats_last = now;
            }
        }

        Ok(())
    })();

    let flush_result = flush_savefile(&mut savefile);
    if let Err(err) = &flush_result {
        accounting
            .output_errors
            .push(format!("pcap flush error: {err}"));
    }
    let capture_result = match (capture_result, flush_result) {
        (Err(capture_err), Err(flush_err)) => Err(std::io::Error::other(format!(
            "{}; pcap flush error: {}",
            capture_err, flush_err
        ))
        .into()),
        (Err(err), Ok(())) => Err(err),
        (Ok(()), Err(err)) => Err(Box::new(err) as Box<dyn std::error::Error>),
        (Ok(()), Ok(())) => Ok(()),
    };

    // Always shut down worker/aggregator threads before returning, including
    // capture/savefile error paths.
    pipe.shutdown();
    let worker_stats = pipe.aggregator.worker_stats();
    accounting.dispatched_frames = Some(accounting.dispatched_frames.unwrap_or(0));
    accounting.dispatch_drops = Some(pipe.stats.dispatch_drops_total());
    accounting.worker_processed_frames = Some(worker_stats.processed_frames);
    accounting.worker_failures = Some(
        accounting
            .dispatched_frames
            .unwrap_or(0)
            .saturating_sub(worker_stats.processed_frames),
    );
    accounting.packets_parsed = worker_stats.parsed_packets;
    accounting.packets_with_transport_header = worker_stats.packets_with_transport_header;
    accounting.malformed_or_unsupported_packets = worker_stats.malformed_or_unsupported_packets;
    accounting.flows_created = worker_stats.flows.created;
    accounting.flows_expired = worker_stats.flows.expired;
    accounting.flows_evicted = worker_stats.flows.evicted;
    accounting.alerts_emitted = pipe.aggregator.alert_count();
    accounting
        .output_errors
        .extend(pipe.aggregator.output_errors());

    // Export flows from aggregated shard snapshots (shutdown() joins all
    // worker threads, so snapshots are guaranteed to be present).
    if config.output.export_json.is_some() || config.output.export_csv.is_some() {
        let snapshot = pipe.aggregator.take_final_snapshots();
        if let Some(path) = &config.output.export_json {
            if let Err(err) = flow::write_flow_json(path.as_ref(), &snapshot) {
                accounting.output_errors.push(format!(
                    "flow JSON export '{}' failed: {err}",
                    path.display()
                ));
                return Err(err);
            }
            println!("  Flow export (JSON): {}", path.display());
        }
        if let Some(path) = &config.output.export_csv {
            if let Err(err) = flow::write_flow_csv(path.as_ref(), &snapshot) {
                accounting.output_errors.push(format!(
                    "flow CSV export '{}' failed: {err}",
                    path.display()
                ));
                return Err(err);
            }
            println!("  Flow export (CSV):  {}", path.display());
        }
    }

    if let Some(err) = pipe.aggregator.take_fatal_error() {
        return match capture_result {
            Ok(()) => Err(std::io::Error::other(err).into()),
            Err(capture_err) => Err(std::io::Error::other(format!(
                "pipeline error: {}; capture error: {}",
                err, capture_err
            ))
            .into()),
        };
    }
    capture_result
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    capture: config::CaptureConfig,
    run: config::RunConfig,
    output: config::OutputConfig,
    flow: config::FlowConfig,
    stats: config::StatsConfig,
    analysis: config::AnalysisConfig,
    web: config::WebConfig,
    pipeline: config::PipelineConfig,
    verbose_level: u8,
}

impl RuntimeConfig {
    fn validate(&self) -> Result<(), config::ConfigError> {
        if self.capture.interface.is_some() && self.capture.read_pcap.is_some() {
            return Err(config::ConfigError::Validation(
                "capture.interface and capture.read_pcap are mutually exclusive".into(),
            ));
        }

        if self.capture.snaplen < 0 {
            return Err(config::ConfigError::Validation(
                "capture.snaplen must be >= 0".into(),
            ));
        }

        if self.capture.timeout_ms < 0 {
            return Err(config::ConfigError::Validation(
                "capture.timeout_ms must be >= 0".into(),
            ));
        }

        let rotate_mb = self.output.write_pcap_rotate_mb;
        let max_files = self.output.write_pcap_max_files;
        let rotation_requested = rotate_mb > 0 || max_files > 0;
        if rotation_requested {
            if self.output.write_pcap.is_none() {
                return Err(config::ConfigError::Validation(
                    "output.write_pcap must be set when pcap rotation is enabled".into(),
                ));
            }
            if rotate_mb == 0 || max_files == 0 {
                return Err(config::ConfigError::Validation(
                    "output.write_pcap_rotate_mb and output.write_pcap_max_files must both be > 0 when rotation is enabled".into(),
                ));
            }
        }

        if !self.flow.timeout_secs.is_finite() || self.flow.timeout_secs < 0.0 {
            return Err(config::ConfigError::Validation(
                "flow.timeout_secs must be >= 0".into(),
            ));
        }

        if self.pipeline.enabled && self.pipeline.channel_capacity == 0 {
            return Err(config::ConfigError::Validation(
                "pipeline.channel_capacity must be > 0".into(),
            ));
        }

        if self.analysis.anomalies.enabled {
            let syn = &self.analysis.anomalies.syn_flood;
            if syn.enabled {
                if !syn.window_secs.is_finite() || syn.window_secs <= 0.0 {
                    return Err(config::ConfigError::Validation(
                        "analysis.anomalies.syn_flood.window_secs must be > 0".into(),
                    ));
                }
                if syn.syn_threshold == 0 {
                    return Err(config::ConfigError::Validation(
                        "analysis.anomalies.syn_flood.syn_threshold must be > 0".into(),
                    ));
                }
                if syn.unique_src_threshold == 0 {
                    return Err(config::ConfigError::Validation(
                        "analysis.anomalies.syn_flood.unique_src_threshold must be > 0".into(),
                    ));
                }
                if !syn.cooldown_secs.is_finite() || syn.cooldown_secs < 0.0 {
                    return Err(config::ConfigError::Validation(
                        "analysis.anomalies.syn_flood.cooldown_secs must be >= 0".into(),
                    ));
                }
            }

            let scan = &self.analysis.anomalies.port_scan;
            if scan.enabled {
                if !scan.window_secs.is_finite() || scan.window_secs <= 0.0 {
                    return Err(config::ConfigError::Validation(
                        "analysis.anomalies.port_scan.window_secs must be > 0".into(),
                    ));
                }
                if scan.unique_ports_threshold == 0 && scan.unique_hosts_threshold == 0 {
                    return Err(config::ConfigError::Validation(
                        "analysis.anomalies.port_scan must set at least one non-zero threshold"
                            .into(),
                    ));
                }
                if !scan.cooldown_secs.is_finite() || scan.cooldown_secs < 0.0 {
                    return Err(config::ConfigError::Validation(
                        "analysis.anomalies.port_scan.cooldown_secs must be >= 0".into(),
                    ));
                }
            }
        }

        if self.web.enabled {
            self.web
                .validate()
                .map_err(config::ConfigError::Validation)?;
        }

        Ok(())
    }
}

fn override_value<T: Clone>(dst: &mut T, src: &Option<T>) {
    if let Some(value) = src {
        *dst = value.clone();
    }
}

fn override_option<T: Clone>(dst: &mut Option<T>, src: &Option<T>) {
    if let Some(value) = src {
        *dst = Some(value.clone());
    }
}

fn override_clearable_path(dst: &mut Option<PathBuf>, src: &Option<PathBuf>) {
    if let Some(value) = src {
        if value.as_os_str().is_empty() {
            *dst = None;
        } else {
            *dst = Some(value.clone());
        }
    }
}

fn override_bool(dst: &mut bool, enable: bool, disable: bool) {
    if enable {
        *dst = true;
    }
    if disable {
        *dst = false;
    }
}

fn load_config(args: &cli::Cli) -> Result<RuntimeConfig, config::ConfigError> {
    let base = match &args.config {
        Some(path) => config::Config::load(path)?,
        None => config::Config::default(),
    };

    let mut capture = base.capture.clone();
    let mut run = base.run.clone();
    let mut output = base.output.clone();
    let mut flow = base.flow.clone();
    let mut stats = base.stats.clone();
    let mut analysis = base.analysis.clone();
    let mut web = base.web.clone();

    if let Some(value) = &args.interface {
        capture.interface = Some(value.clone());
        capture.read_pcap = None;
    }
    if let Some(value) = &args.read_pcap {
        if value.as_os_str().is_empty() {
            capture.read_pcap = None;
        } else {
            capture.read_pcap = Some(value.clone());
            capture.interface = None;
        }
    }
    override_option(&mut capture.filter, &args.filter);
    override_value(&mut run.count, &args.count);
    override_value(&mut capture.snaplen, &args.snaplen);
    override_value(&mut capture.timeout_ms, &args.timeout_ms);
    override_value(&mut stats.interval_ms, &args.stats_interval_ms);
    override_value(&mut stats.top_flows, &args.top_flows);
    override_value(&mut flow.timeout_secs, &args.flow_timeout_s);
    override_value(&mut flow.max_flows, &args.max_flows);
    override_option(&mut output.write_pcap, &args.write_pcap);
    override_value(&mut output.write_pcap_rotate_mb, &args.write_pcap_rotate_mb);
    override_value(&mut output.write_pcap_max_files, &args.write_pcap_max_files);
    override_option(&mut output.export_json, &args.export_json);
    override_option(&mut output.export_csv, &args.export_csv);
    override_option(&mut output.summary_json, &args.summary_json);
    override_clearable_path(&mut analysis.alerts_jsonl, &args.alerts_jsonl);
    override_clearable_path(&mut output.expired_flows_jsonl, &args.expired_flows_jsonl);
    override_clearable_path(&mut output.expired_flows_csv, &args.expired_flows_csv);

    override_bool(
        &mut capture.promiscuous,
        args.promiscuous,
        args.no_promiscuous,
    );
    override_bool(&mut output.hex_dump, args.hex_dump, args.no_hex_dump);
    override_bool(&mut output.quiet, args.quiet, args.no_quiet);
    override_bool(&mut stats.enabled, args.stats, args.no_stats);
    override_bool(
        &mut analysis.anomalies.enabled,
        args.anomalies,
        args.no_anomalies,
    );
    override_bool(&mut web.enabled, args.web, args.no_web);

    override_value(&mut web.bind, &args.web_bind);
    override_value(&mut web.port, &args.web_port);
    override_bool(&mut web.tls.enabled, args.web_tls, args.no_web_tls);
    override_clearable_path(&mut web.tls.cert_path, &args.web_tls_cert);
    override_clearable_path(&mut web.tls.key_path, &args.web_tls_key);
    override_bool(&mut web.auth.enabled, args.web_auth, args.no_web_auth);
    override_value(&mut web.auth.username, &args.web_auth_user);
    if let Some(value) = &args.web_auth_pass_file {
        if value.as_os_str().is_empty() {
            web.auth.password_file = None;
        } else {
            web.auth.password_file = Some(value.clone());
            web.auth.password = None;
        }
    }
    web.normalize();

    let mut pipeline = base.pipeline.clone();
    if args.pipeline {
        pipeline.enabled = true;
    }
    if args.workers > 0 {
        pipeline.workers = args.workers;
        pipeline.enabled = true;
    }

    Ok(RuntimeConfig {
        capture,
        run,
        output,
        flow,
        stats,
        analysis,
        web,
        pipeline,
        verbose_level: args.verbose,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn empty_cli() -> cli::Cli {
        cli::Cli::parse_from(["netscope"])
    }

    fn write_temp_config(contents: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be valid")
            .as_nanos();
        let pid = std::process::id();
        path.push(format!("netscope-test-{}-{}.toml", pid, ts));
        fs::write(&path, contents).expect("config should be written");
        path
    }

    fn write_single_packet_pcap(path: &Path, packet: &[u8]) {
        use std::io::Write;

        let mut file = fs::File::create(path).expect("pcap should be created");
        file.write_all(&0xa1b2c3d4u32.to_le_bytes())
            .expect("pcap magic should be written");
        file.write_all(&2u16.to_le_bytes())
            .expect("pcap major version should be written");
        file.write_all(&4u16.to_le_bytes())
            .expect("pcap minor version should be written");
        file.write_all(&0i32.to_le_bytes())
            .expect("pcap timezone should be written");
        file.write_all(&0u32.to_le_bytes())
            .expect("pcap sigfigs should be written");
        file.write_all(&65535u32.to_le_bytes())
            .expect("pcap snaplen should be written");
        file.write_all(&1u32.to_le_bytes())
            .expect("pcap link type should be written");
        file.write_all(&1u32.to_le_bytes())
            .expect("packet timestamp should be written");
        file.write_all(&0u32.to_le_bytes())
            .expect("packet timestamp fraction should be written");
        file.write_all(&(packet.len() as u32).to_le_bytes())
            .expect("packet captured length should be written");
        file.write_all(&(packet.len() as u32).to_le_bytes())
            .expect("packet wire length should be written");
        file.write_all(packet)
            .expect("packet data should be written");
    }

    fn test_tcp_ethernet_packet(src_last_octet: u8, dst_last_octet: u8) -> Vec<u8> {
        let packet = vec![
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff, // destination MAC
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55, // source MAC
            0x08,
            0x00, // IPv4
            0x45,
            0x00,
            0x00,
            0x28, // version/IHL, TOS, total length
            0x00,
            0x01,
            0x00,
            0x00, // identification, fragment flags
            64,
            6,
            0x00,
            0x00, // TTL, TCP, checksum
            10,
            0,
            0,
            src_last_octet, // source IPv4 address
            10,
            0,
            0,
            dst_last_octet, // destination IPv4 address
            0x30,
            0x39,
            0x00,
            0x50, // source/destination ports
            0x00,
            0x00,
            0x00,
            0x01, // sequence number
            0x00,
            0x00,
            0x00,
            0x00, // acknowledgment number
            0x50,
            0x10,
            0x20,
            0x00, // data offset/flags, window
            0x00,
            0x00,
            0x00,
            0x00, // checksum, urgent pointer
        ];
        packet
    }

    fn unique_test_path(name: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "netscope-test-{}-{}-{}",
            name,
            std::process::id(),
            ts
        ))
    }

    #[test]
    fn live_dispatch_drop_keeps_capture_pcap_and_counts_the_drop() {
        use crossbeam_channel::bounded;

        let dir = unique_test_path("live-dispatch-drop");
        fs::create_dir_all(&dir).expect("test directory should be created");
        let input_path = dir.join("input.pcap");
        let output_path = dir.join("captured.pcap");
        let dropped_packet = test_tcp_ethernet_packet(3, 4);
        write_single_packet_pcap(&input_path, &dropped_packet);

        {
            let mut capture = CaptureSource::Offline(
                pcap::Capture::from_file(&input_path).expect("input pcap should open"),
            );
            let mut output = RotatingSavefile::open(&mut capture, &output_path, None)
                .expect("capture output should open");
            let packet = match capture.next_packet().expect("input packet should read") {
                CaptureRead::Packet(packet) => packet,
                CaptureRead::Idle | CaptureRead::Eof => {
                    panic!("input pcap should contain one packet")
                }
            };

            let (sender, receiver) = bounded(1);
            let queued_packet = test_tcp_ethernet_packet(1, 2);
            sender
                .send(pipeline::OwnedPacket {
                    id: 0,
                    ts: 0.0,
                    wire_len: queued_packet.len() as u64,
                    data: queued_packet.clone(),
                })
                .expect("queue should accept its first packet");
            let senders = [sender];
            let buffer_pool = pipeline::PacketBufPool::new(1, 64);
            let stats = pipeline::PipelineStats::new();
            let dispatcher = PipelinePacketDispatcher {
                capture_mode: CaptureMode::Live,
                link_type: protocol::LinkType::Ethernet,
                senders: &senders,
                buffer_pool: &buffer_pool,
                stats: &stats,
            };
            let mut accounting = RunAccounting {
                frames_read: 1,
                dispatched_frames: Some(0),
                dispatch_drops: Some(0),
                ..RunAccounting::default()
            };
            let mut savefile = Some(&mut output);

            dispatcher
                .write_and_dispatch(&packet, 1, &mut savefile, &mut accounting)
                .expect("a full live queue should count a drop without failing capture");

            assert_eq!(accounting.frames_read, 1);
            assert_eq!(accounting.dispatched_frames, Some(0));
            assert_eq!(accounting.dispatch_drops, Some(1));
            assert_eq!(stats.dispatch_drops_total(), 1);
            assert_eq!(
                receiver.len(),
                1,
                "the dropped packet must not enter the queue"
            );
            let accepted = receiver
                .try_recv()
                .expect("original queued packet should remain");
            assert_eq!(accepted.data, queued_packet);
            assert!(
                receiver.try_recv().is_err(),
                "no second packet should be queued"
            );

            let parsed =
                protocol::parse_packet_with_linktype(&accepted.data, protocol::LinkType::Ethernet)
                    .expect("the accepted packet should parse");
            let mut worker_flows = flow::FlowTracker::new(60.0, 1024, false, false, false);
            worker_flows.observe(accepted.ts, accepted.wire_len, &parsed);
            let flow_export_path = dir.join("flows.json");
            flow::write_flow_json(&flow_export_path, &worker_flows.snapshot())
                .expect("accepted worker packet should be exported");
            let flow_export: serde_json::Value = serde_json::from_slice(
                &fs::read(&flow_export_path).expect("flow export should exist"),
            )
            .expect("flow export should be valid JSON");
            assert_eq!(flow_export.as_array().expect("flow array").len(), 1);
            assert_eq!(flow_export[0]["packets_total"], 1);
            assert_eq!(flow_export[0]["endpoint_a"]["ip"], "10.0.0.1");
            assert_eq!(flow_export[0]["endpoint_b"]["ip"], "10.0.0.2");

            flush_savefile(&mut savefile).expect("capture pcap should flush");
        }

        let mut saved_capture =
            pcap::Capture::from_file(&output_path).expect("written pcap should open");
        let saved_packet = saved_capture
            .next_packet()
            .expect("captured packet should remain in the output pcap");
        assert_eq!(saved_packet.data, dropped_packet);
        assert!(matches!(
            saved_capture.next_packet(),
            Err(pcap::Error::NoMorePackets)
        ));

        fs::remove_dir_all(&dir).expect("test directory should be removed");
    }

    #[test]
    fn cli_clearable_paths_override_config() {
        let path = write_temp_config(
            r#"
[analysis]
alerts_jsonl = "alerts.jsonl"

[output]
expired_flows_jsonl = "expired.jsonl"
"#,
        );

        let mut args = empty_cli();
        args.config = Some(path.clone());
        args.alerts_jsonl = Some(PathBuf::from(""));
        args.expired_flows_jsonl = Some(PathBuf::from(""));

        let cfg = load_config(&args).expect("config should load");

        assert!(cfg.analysis.alerts_jsonl.is_none());
        assert!(cfg.output.expired_flows_jsonl.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn validation_skips_web_when_disabled() {
        let mut cfg = load_config(&empty_cli()).expect("config should load");
        cfg.web.enabled = false;
        cfg.web.auth.enabled = true;
        cfg.web.auth.username = "".into();
        cfg.web.auth.password = None;
        cfg.web.auth.password_file = None;

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validation_rejects_rotation_without_write_pcap() {
        let mut cfg = load_config(&empty_cli()).expect("config should load");
        cfg.output.write_pcap_rotate_mb = 10;
        cfg.output.write_pcap_max_files = 2;
        cfg.output.write_pcap = None;

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validation_rejects_zero_pipeline_channel_capacity() {
        let mut cfg = load_config(&empty_cli()).expect("config should load");
        cfg.pipeline.enabled = true;
        cfg.pipeline.channel_capacity = 0;

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validation_rejects_invalid_port_scan_thresholds() {
        let mut cfg = load_config(&empty_cli()).expect("config should load");
        cfg.analysis.anomalies.enabled = true;
        cfg.analysis.anomalies.port_scan.enabled = true;
        cfg.analysis.anomalies.port_scan.unique_ports_threshold = 0;
        cfg.analysis.anomalies.port_scan.unique_hosts_threshold = 0;

        assert!(cfg.validate().is_err());
    }
}
