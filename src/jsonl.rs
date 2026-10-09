use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Debug)]
pub struct JsonlSink {
    writer: BufWriter<File>,
}

impl JsonlSink {
    pub fn new(path: &Path) -> Result<Self, std::io::Error> {
        let file = crate::output_file::create(path)?;
        Ok(JsonlSink {
            writer: BufWriter::new(file),
        })
    }

    pub fn write<T: Serialize>(&mut self, record: &T) -> Result<(), std::io::Error> {
        let line = serde_json::to_string(record).map_err(std::io::Error::other)?;
        writeln!(self.writer, "{}", line)
    }

    pub fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush()
    }
}
