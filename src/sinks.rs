use crate::flow::{ExpiredFlowCsvSink, ExpiredFlowEvent};
use crate::jsonl::JsonlSink;
use std::path::Path;

#[derive(Debug)]
pub struct AlertJsonlSink {
    sink: JsonlSink,
}

impl AlertJsonlSink {
    pub fn open(path: &Path) -> Result<Self, std::io::Error> {
        Ok(AlertJsonlSink {
            sink: JsonlSink::new(path).map_err(|err| {
                std::io::Error::new(
                    err.kind(),
                    format!("failed to open alerts jsonl '{}': {}", path.display(), err),
                )
            })?,
        })
    }

    pub fn write_alert(
        &mut self,
        ts: f64,
        kind: &str,
        description: &str,
    ) -> Result<(), std::io::Error> {
        let record = serde_json::json!({
            "ts": ts,
            "kind": kind,
            "description": description,
        });
        self.sink.write(&record).map_err(|err| {
            std::io::Error::new(err.kind(), format!("alert write error: {}", err))
        })?;
        self.sink.flush().map_err(|err| {
            std::io::Error::new(err.kind(), format!("alert flush error: {}", err))
        })?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ExpiredFlowSinks {
    jsonl: Option<JsonlSink>,
    csv: Option<ExpiredFlowCsvSink>,
    errors: Vec<String>,
}

impl ExpiredFlowSinks {
    pub fn open(jsonl: Option<&Path>, csv: Option<&Path>) -> Self {
        let mut errors = Vec::new();
        ExpiredFlowSinks {
            jsonl: open_optional_jsonl_sink(jsonl, "expired flows jsonl", &mut errors),
            csv: open_optional_csv_sink(csv, "expired flows csv", &mut errors),
            errors,
        }
    }

    pub fn enabled(&self) -> bool {
        self.jsonl.is_some() || self.csv.is_some()
    }

    pub fn write_events(&mut self, events: &[ExpiredFlowEvent]) -> Result<(), std::io::Error> {
        if events.is_empty() {
            return Ok(());
        }

        let mut failure = None;
        let mut disable_jsonl = false;
        if let Some(sink) = self.jsonl.as_mut() {
            for event in events {
                if let Err(err) = sink.write(event) {
                    self.errors
                        .push(format!("expired flows jsonl write error: {err}"));
                    tracing::warn!(error = %err, "expired flows jsonl disabled after write error");
                    failure.get_or_insert(err);
                    disable_jsonl = true;
                    break;
                }
            }
            if !disable_jsonl && let Err(err) = sink.flush() {
                self.errors
                    .push(format!("expired flows jsonl flush error: {err}"));
                tracing::warn!(error = %err, "expired flows jsonl disabled after flush error");
                failure.get_or_insert(err);
                disable_jsonl = true;
            }
        }
        if disable_jsonl {
            self.jsonl = None;
        }

        let mut disable_csv = false;
        if let Some(sink) = self.csv.as_mut() {
            for event in events {
                if let Err(err) = sink.write(event) {
                    self.errors
                        .push(format!("expired flows csv write error: {err}"));
                    tracing::warn!(error = %err, "expired flows csv disabled after write error");
                    failure.get_or_insert(err);
                    disable_csv = true;
                    break;
                }
            }
            if !disable_csv && let Err(err) = sink.flush() {
                self.errors
                    .push(format!("expired flows csv flush error: {err}"));
                tracing::warn!(error = %err, "expired flows csv disabled after flush error");
                failure.get_or_insert(err);
                disable_csv = true;
            }
        }
        if disable_csv {
            self.csv = None;
        }

        match failure {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn take_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.errors)
    }
}

#[derive(Debug)]
pub struct OutputSinks {
    pub alerts_jsonl: Option<AlertJsonlSink>,
    pub expired_flows: ExpiredFlowSinks,
    errors: Vec<String>,
}

impl OutputSinks {
    pub fn open(
        alerts_jsonl: Option<&Path>,
        expired_flows_jsonl: Option<&Path>,
        expired_flows_csv: Option<&Path>,
    ) -> Self {
        let mut errors = Vec::new();
        let alerts_jsonl = match alerts_jsonl {
            Some(path) => match AlertJsonlSink::open(path) {
                Ok(sink) => Some(sink),
                Err(err) => {
                    errors.push(format!(
                        "failed to open alerts jsonl '{}': {err}",
                        path.display()
                    ));
                    tracing::warn!(
                        error = %err,
                        path = %path.display(),
                        "alerts jsonl disabled"
                    );
                    None
                }
            },
            None => None,
        };

        OutputSinks {
            alerts_jsonl,
            expired_flows: ExpiredFlowSinks::open(expired_flows_jsonl, expired_flows_csv),
            errors,
        }
    }

    pub fn emit_expired_flows(&self) -> bool {
        self.expired_flows.enabled()
    }

    pub fn write_alert(
        &mut self,
        ts: f64,
        kind: &str,
        description: &str,
    ) -> Result<(), std::io::Error> {
        let mut disable_alerts = false;
        if let Some(sink) = self.alerts_jsonl.as_mut()
            && let Err(err) = sink.write_alert(ts, kind, description)
        {
            self.errors
                .push(format!("alerts jsonl output error: {err}"));
            tracing::warn!(error = %err, "alerts jsonl disabled after write error");
            disable_alerts = true;
            if disable_alerts {
                self.alerts_jsonl = None;
            }
            return Err(err);
        }
        if disable_alerts {
            self.alerts_jsonl = None;
        }
        Ok(())
    }

    pub fn write_expired_flows(
        &mut self,
        events: &[ExpiredFlowEvent],
    ) -> Result<(), std::io::Error> {
        self.expired_flows.write_events(events)
    }

    pub fn take_errors(&mut self) -> Vec<String> {
        let mut errors = std::mem::take(&mut self.errors);
        errors.extend(self.expired_flows.take_errors());
        errors
    }
}

fn open_optional_jsonl_sink(
    path: Option<&Path>,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<JsonlSink> {
    match path {
        Some(path) => match JsonlSink::new(path) {
            Ok(sink) => Some(sink),
            Err(err) => {
                errors.push(format!(
                    "failed to open {} '{}': {err}",
                    label,
                    path.display()
                ));
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    "failed to open {}; output disabled",
                    label
                );
                None
            }
        },
        None => None,
    }
}

fn open_optional_csv_sink(
    path: Option<&Path>,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<ExpiredFlowCsvSink> {
    match path {
        Some(path) => match ExpiredFlowCsvSink::new(path) {
            Ok(sink) => Some(sink),
            Err(err) => {
                errors.push(format!(
                    "failed to open {} '{}': {err}",
                    label,
                    path.display()
                ));
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    "failed to open {}; output disabled",
                    label
                );
                None
            }
        },
        None => None,
    }
}
