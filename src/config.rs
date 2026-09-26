use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

fn empty_path_none<'de, D>(deserializer: D) -> Result<Option<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<PathBuf>::deserialize(deserializer)?;
    Ok(opt.and_then(|path| {
        if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        }
    }))
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "config io error: {}", err),
            ConfigError::Parse(err) => write!(f, "config parse error: {}", err),
            ConfigError::Validation(msg) => write!(f, "config validation error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(err) => Some(err),
            ConfigError::Parse(err) => Some(err),
            ConfigError::Validation(_) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub capture: CaptureConfig,
    pub run: RunConfig,
    pub output: OutputConfig,
    pub flow: FlowConfig,
    pub stats: StatsConfig,
    pub analysis: AnalysisConfig,
    pub web: WebConfig,
    pub pipeline: PipelineConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        let mut config: Config = toml::from_str(&raw).map_err(ConfigError::Parse)?;
        config.capture.normalize();
        config.web.normalize();
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    #[serde(deserialize_with = "empty_path_none")]
    pub read_pcap: Option<PathBuf>,
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
            read_pcap: None,
            promiscuous: true,
            snaplen: 65535,
            timeout_ms: 100,
            buffer_size_mb: None,
            immediate_mode: false,
            filter: None,
        }
    }
}

impl CaptureConfig {
    /// Normalize/validate capture config values after deserialization.
    /// `buffer_size_mb = 0` is treated as unset (use the pcap default).
    pub fn normalize(&mut self) {
        if self.buffer_size_mb == Some(0) {
            self.buffer_size_mb = None;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct RunConfig {
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct OutputConfig {
    #[serde(deserialize_with = "empty_path_none")]
    pub write_pcap: Option<PathBuf>,
    pub write_pcap_rotate_mb: u64,
    pub write_pcap_max_files: usize,
    #[serde(deserialize_with = "empty_path_none")]
    pub export_json: Option<PathBuf>,
    #[serde(deserialize_with = "empty_path_none")]
    pub export_csv: Option<PathBuf>,
    #[serde(deserialize_with = "empty_path_none")]
    pub summary_json: Option<PathBuf>,
    #[serde(deserialize_with = "empty_path_none")]
    pub expired_flows_jsonl: Option<PathBuf>,
    #[serde(deserialize_with = "empty_path_none")]
    pub expired_flows_csv: Option<PathBuf>,
    pub hex_dump: bool,
    pub quiet: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FlowConfig {
    pub timeout_secs: f64,
    pub max_flows: usize,
}

impl Default for FlowConfig {
    fn default() -> Self {
        FlowConfig {
            timeout_secs: 60.0,
            max_flows: 100_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StatsConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub top_flows: u32,
}

impl Default for StatsConfig {
    fn default() -> Self {
        StatsConfig {
            enabled: false,
            interval_ms: 1000,
            top_flows: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    pub rtt: bool,
    pub retrans: bool,
    pub out_of_order: bool,
    pub anomalies: AnomalyConfig,
    #[serde(deserialize_with = "empty_path_none")]
    pub alerts_jsonl: Option<PathBuf>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            rtt: true,
            retrans: true,
            out_of_order: true,
            anomalies: AnomalyConfig::default(),
            alerts_jsonl: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AnomalyConfig {
    pub enabled: bool,
    pub syn_flood: SynFloodConfig,
    pub port_scan: PortScanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SynFloodConfig {
    pub enabled: bool,
    pub window_secs: f64,
    pub syn_threshold: u32,
    pub unique_src_threshold: u32,
    pub cooldown_secs: f64,
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        SynFloodConfig {
            enabled: true,
            window_secs: 5.0,
            syn_threshold: 200,
            unique_src_threshold: 50,
            cooldown_secs: 10.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PortScanConfig {
    pub enabled: bool,
    pub window_secs: f64,
    pub unique_ports_threshold: u32,
    pub unique_hosts_threshold: u32,
    pub cooldown_secs: f64,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        PortScanConfig {
            enabled: true,
            window_secs: 10.0,
            unique_ports_threshold: 25,
            unique_hosts_threshold: 10,
            cooldown_secs: 30.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Enable the web dashboard.
    pub enabled: bool,
    /// Address to bind the HTTP server to.
    pub bind: String,
    /// Port for the HTTP server.
    pub port: u16,
    /// How often (ms) to push stats ticks to connected clients.
    pub tick_ms: u64,
    /// Number of top flows to include in each tick.
    pub top_n: usize,
    /// Number of packets to keep in the detail ring buffer.
    pub packet_buffer: usize,
    /// Sample every Nth packet for the live packet feed (1 = every packet).
    pub sample_rate: u64,
    /// Max payload bytes to store per packet for hex dump display.
    pub payload_bytes: usize,
    /// TLS settings for HTTPS dashboard serving.
    pub tls: WebTlsConfig,
    /// Authentication settings for dashboard endpoints.
    pub auth: WebAuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WebTlsConfig {
    /// Enable HTTPS for the dashboard.
    pub enabled: bool,
    /// PEM certificate file path.
    #[serde(deserialize_with = "empty_path_none")]
    pub cert_path: Option<PathBuf>,
    /// PEM private key file path.
    #[serde(deserialize_with = "empty_path_none")]
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WebAuthConfig {
    /// Enable HTTP Basic authentication for all dashboard endpoints.
    pub enabled: bool,
    /// Username for HTTP Basic auth.
    pub username: String,
    /// Inline password for HTTP Basic auth.
    pub password: Option<String>,
    /// File containing the HTTP Basic auth password.
    #[serde(deserialize_with = "empty_path_none")]
    pub password_file: Option<PathBuf>,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            enabled: false,
            bind: "127.0.0.1".into(),
            port: 8080,
            tick_ms: 1000,
            top_n: 10,
            packet_buffer: 2000,
            sample_rate: 1,
            payload_bytes: 256,
            tls: WebTlsConfig::default(),
            auth: WebAuthConfig::default(),
        }
    }
}

impl WebConfig {
    pub const MIN_TICK_MS: u64 = 16;

    pub fn normalize(&mut self) {
        self.tick_ms = self.tick_ms.max(Self::MIN_TICK_MS);
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.tls.enabled {
            if self.tls.cert_path.is_none() {
                return Err("web.tls.cert_path is required when web.tls.enabled = true".into());
            }
            if self.tls.key_path.is_none() {
                return Err("web.tls.key_path is required when web.tls.enabled = true".into());
            }
        }

        if self.auth.enabled {
            if self.auth.username.trim().is_empty() {
                return Err("web.auth.username is required when web.auth.enabled = true".into());
            }

            let has_password = self
                .auth
                .password
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty());
            let has_password_file = self.auth.password_file.is_some();

            match (has_password, has_password_file) {
                (true, false) | (false, true) => {}
                (false, false) => {
                    return Err(
                        "web.auth.password or web.auth.password_file is required when web.auth.enabled = true"
                            .into(),
                    );
                }
                (true, true) => {
                    return Err(
                        "web.auth.password and web.auth.password_file are mutually exclusive"
                            .into(),
                    );
                }
            }
        }

        Ok(())
    }
}

impl WebAuthConfig {
    pub fn resolve_password(&self) -> Result<Option<String>, String> {
        if !self.enabled {
            return Ok(None);
        }

        if let Some(password) = &self.password {
            let trimmed = password.trim_end_matches(['\r', '\n']);
            if !trimmed.trim().is_empty() {
                return Ok(Some(trimmed.to_string()));
            }

            // Treat empty inline password as unset so password_file can be used
            // alongside template defaults such as password = "".
            if self.password_file.is_none() {
                return Err("web.auth.password cannot be empty".into());
            }
        }

        if let Some(path) = &self.password_file {
            let raw = std::fs::read_to_string(path).map_err(|err| {
                format!(
                    "failed to read web.auth.password_file '{}': {}",
                    path.display(),
                    err
                )
            })?;
            let trimmed = raw.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                return Err(format!(
                    "web.auth.password_file '{}' is empty",
                    path.display()
                ));
            }
            return Ok(Some(trimmed.to_string()));
        }

        Err("web auth password is not configured".into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PipelineConfig {
    /// Enable the sharded pipeline.
    pub enabled: bool,
    /// Number of worker threads (0 = auto-detect).
    pub workers: usize,
    /// Capacity of each capture → worker channel.
    pub channel_capacity: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            enabled: false,
            workers: 0,
            channel_capacity: 4096,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn web_tick_ms_normalize_keeps_valid_value() {
        let mut web = WebConfig {
            tick_ms: 33,
            ..WebConfig::default()
        };

        web.normalize();

        assert_eq!(web.tick_ms, 33);
    }

    #[test]
    fn web_tick_ms_normalize_clamps_low_value() {
        let mut web = WebConfig {
            tick_ms: 1,
            ..WebConfig::default()
        };

        web.normalize();

        assert_eq!(web.tick_ms, WebConfig::MIN_TICK_MS);
    }

    #[test]
    fn web_validate_defaults() {
        let web = WebConfig::default();
        assert!(web.validate().is_ok());
    }

    #[test]
    fn web_validate_rejects_tls_without_cert() {
        let web = WebConfig {
            tls: WebTlsConfig {
                enabled: true,
                cert_path: None,
                key_path: Some(PathBuf::from("key.pem")),
            },
            ..WebConfig::default()
        };

        let err = web.validate().expect_err("expected tls validation error");
        assert!(err.contains("web.tls.cert_path"));
    }

    #[test]
    fn web_validate_rejects_auth_without_secret() {
        let web = WebConfig {
            auth: WebAuthConfig {
                enabled: true,
                username: "netscope".into(),
                password: None,
                password_file: None,
            },
            ..WebConfig::default()
        };

        let err = web.validate().expect_err("expected auth validation error");
        assert!(err.contains("web.auth.password"));
    }

    #[test]
    fn web_validate_rejects_auth_dual_secret_sources() {
        let web = WebConfig {
            auth: WebAuthConfig {
                enabled: true,
                username: "netscope".into(),
                password: Some("inline".into()),
                password_file: Some(PathBuf::from("password.txt")),
            },
            ..WebConfig::default()
        };

        let err = web.validate().expect_err("expected auth validation error");
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn web_auth_resolve_password_from_file_trims_newline() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("netscope-web-auth-{}.txt", unique));

        fs::write(&path, "secret\n").expect("failed to write temp password file");

        let auth = WebAuthConfig {
            enabled: true,
            username: "netscope".into(),
            password: None,
            password_file: Some(path.clone()),
        };

        let resolved = auth
            .resolve_password()
            .expect("failed to resolve password")
            .expect("password should be present");

        assert_eq!(resolved, "secret");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn web_auth_resolve_password_uses_file_when_inline_password_is_empty() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("netscope-web-auth-fallback-{}.txt", unique));

        fs::write(&path, "from-file\n").expect("failed to write temp password file");

        let auth = WebAuthConfig {
            enabled: true,
            username: "netscope".into(),
            password: Some(String::new()),
            password_file: Some(path.clone()),
        };

        let resolved = auth
            .resolve_password()
            .expect("failed to resolve password")
            .expect("password should be present");

        assert_eq!(resolved, "from-file");

        let _ = fs::remove_file(path);
    }
}
