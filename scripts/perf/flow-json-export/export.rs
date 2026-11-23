use netscope::capture::engine::open_offline;
use netscope::flow::{FlowTracker, write_flow_json};
use netscope::protocol::{LinkType, parse_packet_with_linktype};
use std::path::Path;
use std::time::Instant;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let count: usize = args[2].parse().unwrap();
    let mut capture = open_offline(Path::new(&args[1]), None).unwrap();
    let mut tracker = FlowTracker::new(0.0, count, false, false, false);
    for _ in 0..count {
        let packet = capture.next_packet().unwrap();
        let parsed = parse_packet_with_linktype(packet.data, LinkType::Ethernet).unwrap();
        let timestamp =
            packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        tracker.observe(timestamp, u64::from(packet.header.len), &parsed);
    }
    let mut flows = tracker.snapshot();
    assert_eq!(flows.len(), count);
    // The tracker's hash map has a per-process seed. Set a fixed order so
    // every export serializes the same rows in the same sequence.
    flows.sort_unstable_by_key(|flow| {
        (
            flow.endpoint_a.ip,
            flow.endpoint_a.port,
            flow.endpoint_b.ip,
            flow.endpoint_b.port,
        )
    });

    let output = Path::new(&args[3]);
    let start = Instant::now();
    write_flow_json(output, &flows).unwrap();
    let elapsed = start.elapsed();

    let bytes = std::fs::metadata(output).unwrap().len();
    println!("{} {bytes}", elapsed.as_nanos());
}
