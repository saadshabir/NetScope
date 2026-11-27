use super::{emit_capture_ready, read_packet};
use crate::capture_source::{CaptureMode, CaptureRead, CaptureSource, packet_timestamp};
use crate::pcap_rotation::{RotatingSavefile, flush_savefile, write_packet_to_savefile};
use crate::runtime_config::RuntimeConfig;

use netscope::run_summary::RunAccounting;
#[cfg(feature = "dashboard")]
use netscope::web;
use netscope::{flow, pipeline, protocol};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

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
            ts: packet_timestamp(packet),
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

/// Sharded pipeline capture loop: the main thread only reads from pcap
/// and dispatches owned packet buffers to worker shards.
pub(super) fn run_capture_pipeline(
    config: &RuntimeConfig,
    running: &Arc<AtomicBool>,
    link_type: protocol::LinkType,
    cap: &mut CaptureSource,
    mut savefile: Option<&mut RotatingSavefile>,
    #[cfg(feature = "dashboard")] web_handle: Option<&web::server::WebHandle>,
    accounting: &mut RunAccounting,
) -> Result<(), Box<dyn std::error::Error>> {
    // The pool starts with small buffers and grows them for larger frames.
    // Snaplen controls how much grown-buffer capacity it retains.
    let packet_buf_size = match config.capture.snaplen {
        s if s > 0 => s as usize,
        _ => 65535,
    };
    let kernel_stats = Arc::new(pipeline::KernelPcapStats::new());
    let stats_top_n = if config.stats.enabled {
        config.stats.top_flows as usize
    } else {
        0
    };
    let web_top_n = if config.web.enabled {
        config.web.top_n
    } else {
        0
    };

    let pipeline_cfg = pipeline::PipelineConfig {
        offline: matches!(cap.mode(), CaptureMode::Offline),
        num_workers: config.pipeline.workers,
        channel_capacity: config.pipeline.channel_capacity,
        buffer_pool_capacity: config.pipeline.channel_capacity.saturating_mul(2).max(1),
        packet_buf_size,
        flow: config.flow.clone(),
        analysis: config.analysis.clone(),
        stats: config.stats.clone(),
        web: config.web.clone(),
        heavy_hitter_top_n: stats_top_n.max(web_top_n),
        collect_final_flows: config.output.export_json.is_some()
            || config.output.export_csv.is_some(),
        alerts_jsonl: config.analysis.alerts_jsonl.clone(),
        expired_flows_jsonl: config.output.expired_flows_jsonl.clone(),
        expired_flows_csv: config.output.expired_flows_csv.clone(),
        kernel_stats: kernel_stats.clone(),
        link_type,
    };

    let mut pipe = pipeline::spawn(
        pipeline_cfg,
        running.clone(),
        #[cfg(feature = "dashboard")]
        web_handle,
    )?;
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
    emit_capture_ready(config, Some(num_workers));

    let mut stats_last = Instant::now();
    let mut live_stats_poll_last = cap.start_live_stats_poll();

    let capture_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        while running.load(Ordering::SeqCst) {
            if config.run.count > 0 && accounting.frames_read >= config.run.count {
                break;
            }

            match read_packet(cap, &mut savefile)? {
                CaptureRead::Packet(packet) => {
                    let packet_count = accounting.record_input_frame(packet.header.len as u64);
                    dispatcher.write_and_dispatch(
                        &packet,
                        packet_count,
                        &mut savefile,
                        accounting,
                    )?;
                }
                CaptureRead::Idle => {}
                CaptureRead::Eof => break,
            }

            if let Some((dropped_total, if_dropped_total)) =
                cap.poll_live_pcap_stats(&mut live_stats_poll_last)
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
    accounting.packets_with_network_header = worker_stats.packets_with_network_header;
    accounting.packets_with_transport_header = worker_stats.packets_with_transport_header;
    accounting.packet_parse_errors = worker_stats.packet_parse_errors;
    accounting.transport_parse_errors = worker_stats.transport_parse_errors;
    accounting.unsupported_packets = worker_stats.unsupported_packets;
    accounting.malformed_or_unsupported_packets = worker_stats.malformed_or_unsupported_packets;
    accounting.flows_created = worker_stats.flows.created;
    accounting.flows_expired = worker_stats.flows.expired;
    accounting.flows_evicted = worker_stats.flows.evicted;
    accounting.alerts_emitted = 0;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

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
            let output_config = netscope::config::OutputConfig {
                write_pcap: Some(output_path.clone()),
                ..Default::default()
            };
            let mut output = RotatingSavefile::open(&mut capture, &output_config)
                .expect("capture output should open")
                .expect("capture output is configured");
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
}
