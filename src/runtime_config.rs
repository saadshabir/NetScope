use crate::{cli, output_paths, pcap_rotation};
use netscope::config;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) struct RuntimeConfig {
    config_path: Option<PathBuf>,
    pub(crate) capture: config::CaptureConfig,
    pub(crate) run: config::RunConfig,
    pub(crate) output: config::OutputConfig,
    pub(crate) flow: config::FlowConfig,
    pub(crate) stats: config::StatsConfig,
    pub(crate) analysis: config::AnalysisConfig,
    pub(crate) web: config::WebConfig,
    pub(crate) pipeline: config::PipelineConfig,
    pub(crate) verbose_level: u8,
}

impl RuntimeConfig {
    pub(crate) fn validate(&self) -> Result<(), config::ConfigError> {
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

        if self.pipeline.enabled && self.analysis.anomalies.has_enabled_detector() {
            return Err(config::ConfigError::Validation(
                "pipeline mode does not support anomaly detection because thresholds would be evaluated per worker; disable pipeline or set analysis.anomalies.enabled = false".into(),
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

        self.validate_output_paths()?;
        Ok(())
    }

    fn validate_output_paths(&self) -> Result<(), config::ConfigError> {
        let mut reads = Vec::new();
        if let Some(path) = &self.config_path {
            reads.push(("config file", path.as_path()));
        }
        if let Some(path) = &self.capture.read_pcap {
            reads.push(("capture.read_pcap", path.as_path()));
        }
        if self.web.enabled && self.web.tls.enabled {
            reads.push((
                "web.tls.cert_path",
                self.web
                    .tls
                    .cert_path
                    .as_deref()
                    .expect("validated TLS cert"),
            ));
            reads.push((
                "web.tls.key_path",
                self.web.tls.key_path.as_deref().expect("validated TLS key"),
            ));
        }
        if self.web.enabled
            && self.web.auth.enabled
            && let Some(path) = &self.web.auth.password_file
        {
            reads.push(("web.auth.password_file", path.as_path()));
        }
        let outputs = [
            ("output.write_pcap", self.output.write_pcap.as_deref()),
            ("output.export_json", self.output.export_json.as_deref()),
            ("output.export_csv", self.output.export_csv.as_deref()),
            ("output.summary_json", self.output.summary_json.as_deref()),
            (
                "output.expired_flows_jsonl",
                self.output.expired_flows_jsonl.as_deref(),
            ),
            (
                "output.expired_flows_csv",
                self.output.expired_flows_csv.as_deref(),
            ),
            (
                "analysis.alerts_jsonl",
                self.analysis.alerts_jsonl.as_deref(),
            ),
        ];
        let outputs: Vec<_> = outputs
            .into_iter()
            .filter_map(|(name, path)| path.map(|path| (name, path)))
            .collect();
        output_paths::validate(&reads, &outputs).map_err(config::ConfigError::Validation)?;
        if self.output.write_pcap_rotate_mb > 0 {
            let base = self
                .output
                .write_pcap
                .as_deref()
                .expect("validated rotation base");
            pcap_rotation::validate_segment_paths(base, &reads, &outputs)
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

pub(crate) fn load_config(args: &cli::Cli) -> Result<RuntimeConfig, config::ConfigError> {
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
        config_path: args.config.clone(),
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
