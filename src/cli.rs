use clap::Parser;

/// NetScope: High-performance network packet capture and protocol analyzer
#[derive(Parser, Debug)]
#[command(name = "netscope", version, about)]
pub struct Cli {
    /// Path to a TOML configuration file
    #[arg(long)]
    pub config: Option<std::path::PathBuf>,

    /// Network interface to capture on (e.g., "en0", "eth0").
    /// If not specified, the default interface is used.
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Read packets from an offline pcap file
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["interface", "promiscuous", "no_promiscuous"]
    )]
    pub read_pcap: Option<std::path::PathBuf>,

    /// BPF filter expression (e.g., "tcp port 80", "host 192.168.1.1")
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Maximum number of packets to capture (0 = unlimited)
    #[arg(short = 'c', long)]
    pub count: Option<u64>,

    /// Capture in promiscuous mode
    #[arg(short, long, action = clap::ArgAction::SetTrue, conflicts_with = "no_promiscuous")]
    pub promiscuous: bool,

    /// Disable promiscuous mode
    #[arg(long = "no-promiscuous", action = clap::ArgAction::SetTrue, conflicts_with = "promiscuous")]
    pub no_promiscuous: bool,

    /// Snapshot length (max bytes per packet to capture)
    #[arg(short, long)]
    pub snaplen: Option<i32>,

    /// Read timeout in milliseconds for the capture handle
    #[arg(short = 't', long)]
    pub timeout_ms: Option<i32>,

    /// Show hex dump of packet payload
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "no_hex_dump")]
    pub hex_dump: bool,

    /// Disable hex dump output
    #[arg(long = "no-hex-dump", action = clap::ArgAction::SetTrue, conflicts_with = "hex_dump")]
    pub no_hex_dump: bool,

    /// Suppress per-packet output (useful for stats-only runs)
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "no_quiet")]
    pub quiet: bool,

    /// Enable per-packet output
    #[arg(long = "no-quiet", action = clap::ArgAction::SetTrue, conflicts_with = "quiet")]
    pub no_quiet: bool,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// List available network interfaces and exit
    #[arg(short, long)]
    pub list_interfaces: bool,

    /// Write captured packets to a pcap file
    #[arg(long)]
    pub write_pcap: Option<std::path::PathBuf>,

    /// Rotate --write-pcap output when a file reaches this many MiB
    #[arg(long, value_name = "MB", requires = "write_pcap")]
    pub write_pcap_rotate_mb: Option<u64>,

    /// Maximum number of rotated pcap files to keep
    #[arg(long, value_name = "N", requires = "write_pcap")]
    pub write_pcap_max_files: Option<usize>,

    /// Export flow table to JSON on exit
    #[arg(long)]
    pub export_json: Option<std::path::PathBuf>,

    /// Export flow table to CSV on exit
    #[arg(long)]
    pub export_csv: Option<std::path::PathBuf>,

    /// Write versioned final run accounting as JSON
    #[arg(long)]
    pub summary_json: Option<std::path::PathBuf>,

    /// Enable periodic throughput stats
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "no_stats")]
    pub stats: bool,

    /// Disable periodic throughput stats
    #[arg(long = "no-stats", action = clap::ArgAction::SetTrue, conflicts_with = "stats")]
    pub no_stats: bool,

    /// Stats interval in milliseconds
    #[arg(long)]
    pub stats_interval_ms: Option<u64>,

    /// Number of top flows to show each stats tick
    #[arg(long)]
    pub top_flows: Option<u32>,

    /// Flow inactivity timeout in seconds (0 = disable)
    #[arg(long)]
    pub flow_timeout_s: Option<f64>,

    /// Maximum number of flows to keep (0 = unlimited)
    #[arg(long)]
    pub max_flows: Option<usize>,

    /// Enable anomaly detection alerts
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "no_anomalies")]
    pub anomalies: bool,

    /// Disable anomaly detection alerts
    #[arg(long = "no-anomalies", action = clap::ArgAction::SetTrue, conflicts_with = "anomalies")]
    pub no_anomalies: bool,

    /// Write anomaly alerts as JSON lines
    #[arg(long)]
    pub alerts_jsonl: Option<std::path::PathBuf>,

    /// Write expired flow records as JSON lines
    #[arg(long)]
    pub expired_flows_jsonl: Option<std::path::PathBuf>,

    /// Write expired flow records as CSV (streaming)
    #[arg(long)]
    pub expired_flows_csv: Option<std::path::PathBuf>,

    /// Enable the web dashboard
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "no_web")]
    pub web: bool,

    /// Disable the web dashboard
    #[arg(long = "no-web", action = clap::ArgAction::SetTrue, conflicts_with = "web")]
    pub no_web: bool,

    /// Web dashboard bind address
    #[arg(long)]
    pub web_bind: Option<String>,

    /// Web dashboard port
    #[arg(long)]
    pub web_port: Option<u16>,

    /// Enable HTTPS for the web dashboard
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "no_web_tls")]
    pub web_tls: bool,

    /// Disable HTTPS for the web dashboard
    #[arg(long = "no-web-tls", action = clap::ArgAction::SetTrue, conflicts_with = "web_tls")]
    pub no_web_tls: bool,

    /// PEM certificate file path for web dashboard HTTPS
    #[arg(long)]
    pub web_tls_cert: Option<std::path::PathBuf>,

    /// PEM private key file path for web dashboard HTTPS
    #[arg(long)]
    pub web_tls_key: Option<std::path::PathBuf>,

    /// Enable HTTP Basic auth for the web dashboard
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "no_web_auth")]
    pub web_auth: bool,

    /// Disable HTTP Basic auth for the web dashboard
    #[arg(long = "no-web-auth", action = clap::ArgAction::SetTrue, conflicts_with = "web_auth")]
    pub no_web_auth: bool,

    /// Username for web dashboard HTTP Basic auth
    #[arg(long)]
    pub web_auth_user: Option<String>,

    /// File containing the web dashboard HTTP Basic auth password
    #[arg(long)]
    pub web_auth_pass_file: Option<std::path::PathBuf>,

    /// Enable the sharded pipeline for multi-core packet processing
    #[arg(long)]
    pub pipeline: bool,

    /// Number of worker threads for the pipeline (0 = auto, default: 0)
    #[arg(long, default_value_t = 0)]
    pub workers: usize,

    /// Run a synthetic scale-mode flow memory benchmark and exit
    #[arg(long)]
    pub synthetic_flows: Option<usize>,
}
