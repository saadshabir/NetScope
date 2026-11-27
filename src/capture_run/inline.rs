use super::{emit_capture_ready, read_packet};
use crate::capture_source::{CaptureRead, CaptureSource, packet_timestamp};
use crate::pcap_rotation::{RotatingSavefile, flush_savefile, write_packet_to_savefile};
use crate::runtime_config::RuntimeConfig;

use netscope::run_summary::RunAccounting;
use netscope::{analysis, display, flow, maybe_analyze_anomaly, protocol, sinks};
#[cfg(feature = "dashboard")]
use netscope::{build_packet_data, metrics, web};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[derive(Debug, Default)]
struct InlineKernelStats {
    dropped_total: u64,
    if_dropped_total: u64,
    dropped_interval_stats: u64,
    if_dropped_interval_stats: u64,
    #[cfg(feature = "dashboard")]
    dropped_interval_web: u64,
    #[cfg(feature = "dashboard")]
    if_dropped_interval_web: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct PcapDropSnapshot {
    dropped_total: u64,
    if_dropped_total: u64,
}

#[cfg(feature = "dashboard")]
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
        #[cfg(feature = "dashboard")]
        {
            self.dropped_interval_web = self.dropped_interval_web.saturating_add(dropped_delta);
            self.if_dropped_interval_web = self
                .if_dropped_interval_web
                .saturating_add(if_dropped_delta);
        }
        self.initialized = true;
    }

    fn take_stats_interval(&mut self) -> (u64, u64) {
        let dropped = self.dropped_interval_stats;
        let if_dropped = self.if_dropped_interval_stats;
        self.dropped_interval_stats = 0;
        self.if_dropped_interval_stats = 0;
        (dropped, if_dropped)
    }

    #[cfg(feature = "dashboard")]
    fn take_web_interval(&mut self) -> (u64, u64) {
        let dropped = self.dropped_interval_web;
        let if_dropped = self.if_dropped_interval_web;
        self.dropped_interval_web = 0;
        self.if_dropped_interval_web = 0;
        (dropped, if_dropped)
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

/// Run capture and analysis on the calling thread.
pub(super) fn run_capture_inline(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
    link_type: protocol::LinkType,
    cap: &mut CaptureSource,
    mut savefile: Option<&mut RotatingSavefile>,
    #[cfg(feature = "dashboard")] web_handle: Option<&web::server::WebHandle>,
    accounting: &mut RunAccounting,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();

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
    let mut capture_watermark: Option<f64> = None;

    let mut stats_last = Instant::now();
    let mut stats_bytes: u64 = 0;
    let mut stats_packets: u64 = 0;
    let mut kernel_stats = InlineKernelStats::default();
    let mut live_stats_poll_last = cap.start_live_stats_poll();

    // Web dashboard tick state
    #[cfg(feature = "dashboard")]
    let mut web_tick_last = Instant::now();
    #[cfg(feature = "dashboard")]
    let mut web_tick_bytes: u64 = 0;
    #[cfg(feature = "dashboard")]
    let mut web_tick_packets: u64 = 0;
    #[cfg(feature = "dashboard")]
    let mut web_frame_seq: u64 = 0;

    emit_capture_ready(config, None);

    let capture_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        while running.load(Ordering::SeqCst) {
            // Check packet count limit
            if config.run.count > 0 && accounting.frames_read >= config.run.count {
                break;
            }

            // Read next packet
            let packet = match read_packet(cap, &mut savefile)? {
                CaptureRead::Packet(packet) => Some(packet),
                CaptureRead::Idle => None,
                CaptureRead::Eof => break,
            };

            if let Some(packet) = packet {
                let wire_len = packet.header.len as u64;
                let packet_count = accounting.record_input_frame(wire_len);

                let timestamp = packet_timestamp(&packet);
                capture_watermark =
                    Some(capture_watermark.map_or(timestamp, |ts| ts.max(timestamp)));
                let raw_data = packet.data;

                if let Err(err) = write_packet_to_savefile(&mut savefile, &packet, packet_count) {
                    tracing::error!(error = %err, "pcap write error");
                    accounting
                        .output_errors
                        .push(format!("pcap write error: {err}"));
                    return Err(Box::new(err));
                }

                let result = protocol::parse_packet_with_linktype(raw_data, link_type);
                accounting.record_packet_parse(&result);
                match result {
                    Ok(parsed) => {
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
                                if let Err(err) = output_sinks.write_alert(alert) {
                                    accounting.output_errors.extend(output_sinks.take_errors());
                                    accounting.output_errors.push(err.to_string());
                                    return Err(Box::new(err));
                                }
                                println!("[alert] {}", alert.description);
                                // Forward alerts to web dashboard
                                #[cfg(feature = "dashboard")]
                                if let Some(handle) = web_handle
                                    && handle
                                        .event_tx
                                        .try_send(web::messages::CaptureEvent::Alert(
                                            web::messages::AlertMsg::from(alert),
                                        ))
                                        .is_err()
                                {
                                    tracing::trace!("web event channel full, dropping alert");
                                }
                            }
                        }
                        if emit_expired_flows {
                            flow_tracker.observe_collect(
                                timestamp,
                                wire_len,
                                &parsed,
                                &mut expired_flow_events,
                            );
                            flush_expired_flows_accounted(
                                &mut output_sinks,
                                &mut expired_flow_events,
                                accounting,
                            )?;
                        } else {
                            flow_tracker.observe(timestamp, wire_len, &parsed);
                        }
                        sync_flow_accounting(accounting, &flow_tracker);

                        // Send packet samples to web dashboard.
                        #[cfg(feature = "dashboard")]
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
                        anomaly_detector.advance_time(timestamp);
                        display::print_parse_error(packet_count, timestamp, raw_data.len(), &e);
                        tracing::debug!(error = %e, "parse error on packet #{}", packet_count);
                    }
                }

                stats_bytes += wire_len;
                stats_packets += 1;
                #[cfg(feature = "dashboard")]
                {
                    web_tick_bytes += wire_len;
                    web_tick_packets += 1;
                }

                let watermark = capture_watermark.unwrap_or(timestamp);
                if (watermark - last_expire_check_ts) >= 1.0 {
                    last_expire_check_ts = watermark;
                    if emit_expired_flows {
                        flow_tracker.maybe_expire_collect(watermark, &mut expired_flow_events);
                        flush_expired_flows_accounted(
                            &mut output_sinks,
                            &mut expired_flow_events,
                            accounting,
                        )?;
                    } else {
                        flow_tracker.maybe_expire(watermark);
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

            if let Some((dropped_total, if_dropped_total)) =
                cap.poll_live_pcap_stats(&mut live_stats_poll_last)
            {
                kernel_stats.update_totals(dropped_total, if_dropped_total);
            }

            // Stats printing
            if config.stats.enabled
                && let now = Instant::now()
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
            #[cfg(feature = "dashboard")]
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
                    metrics::set_anomaly_saturation(anomaly_detector.saturation());

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
    accounting.anomaly_saturation = anomaly_detector.saturation();
    #[cfg(feature = "dashboard")]
    if web_handle.is_some() {
        metrics::set_anomaly_saturation(accounting.anomaly_saturation);
    }
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
