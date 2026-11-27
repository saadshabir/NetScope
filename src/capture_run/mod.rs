mod inline;
mod pipeline;

use crate::capture_source::{CaptureMode, CaptureRead, CaptureSource};
use crate::pcap_rotation::{RotatingSavefile, maybe_rotate_savefile};
use crate::runtime_config::RuntimeConfig;

use netscope::protocol;
use netscope::run_summary::{self, RunAccounting, RunSummary};
#[cfg(feature = "dashboard")]
use netscope::web;

use self::inline::run_capture_inline;
use self::pipeline::run_capture_pipeline;

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Main capture loop: open capture, read packets, parse, and display.
pub(crate) fn run_capture(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    config.validate()?;
    let run_start = Instant::now();
    let mut cap = CaptureSource::open(&config.capture)?;
    let link_type = protocol::LinkType::from_pcap_value(cap.get_datalink().0);
    let capture_mode = cap.mode();
    let mut savefile = RotatingSavefile::open(&mut cap, &config.output)?;
    // Start web dashboard if enabled.
    #[cfg(feature = "dashboard")]
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
            #[cfg(feature = "dashboard")]
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
            #[cfg(feature = "dashboard")]
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

    let status = if processing_result.is_err() || !accounting.output_errors.is_empty() {
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
        accounting,
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
    println!("  Packets classified:  {}", summary.packets_parsed);
    println!(
        "  Network headers:    {}",
        summary.packets_with_network_header
    );
    println!(
        "  Transport headers:   {}",
        summary.packets_with_transport_header
    );
    println!("  Packet parse errors: {}", summary.packet_parse_errors);
    println!("  Malformed transport: {}", summary.transport_parse_errors);
    println!("  Unsupported packets:  {}", summary.unsupported_packets);
    println!(
        "  Malformed/unsupported total: {}",
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
    }
    println!("  Flows created:      {}", summary.flows_created);
    println!("  Flows expired:      {}", summary.flows_expired);
    println!("  Flows evicted:      {}", summary.flows_evicted);
    println!("  Alerts emitted:     {}", summary.alerts_emitted);
    if summary.effective_config.anomaly_detection {
        println!(
            "  Anomaly evidence discards: {} SYN flood, {} port scan",
            summary.anomaly_saturation.syn_flood.total(),
            summary.anomaly_saturation.port_scan.total()
        );
    }
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

#[cfg(feature = "dashboard")]
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
        allowed_origins: config.web.allowed_origins.clone(),
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

/// Emit a machine-readable live-capture readiness marker after capture and
/// processing resources are ready. Live harnesses must wait for this event
/// before sending traffic so startup packets cannot be counted as loss.
fn emit_capture_ready(config: &RuntimeConfig, worker_count: Option<usize>) {
    if config.capture.read_pcap.is_some() {
        return;
    }

    let readiness = serde_json::json!({
        "event": "netscope.capture.ready",
        "schema_version": 1,
        "interface": config.capture.interface.as_deref().unwrap_or("(default)"),
        "filter": config.capture.filter.as_deref(),
        "snaplen": config.capture.snaplen,
        "timeout_ms": config.capture.timeout_ms,
        "capture_buffer_size_mb_requested": config.capture.buffer_size_mb,
        "promiscuous": config.capture.promiscuous,
        "immediate_mode": config.capture.immediate_mode,
        "pipeline_enabled": config.pipeline.enabled,
        "workers": worker_count,
        "requested_workers": config.pipeline.workers,
        "channel_capacity": config.pipeline.enabled.then_some(config.pipeline.channel_capacity),
    });
    println!("NETSCOPE_READY {readiness}");
    let _ = std::io::stdout().flush();
}

fn read_packet<'a>(
    cap: &'a mut CaptureSource,
    savefile: &mut Option<&mut RotatingSavefile>,
) -> Result<CaptureRead<'a>, pcap::Error> {
    maybe_rotate_savefile(cap, savefile)
        .inspect_err(|err| tracing::error!(error = %err, "pcap rotate error"))?;
    cap.next_packet()
        .inspect_err(|err| tracing::error!(error = %err, "capture error"))
}
