use crate::{capture_source::CaptureSource, output_paths};
use netscope::config;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

const SAVEFILE_FLUSH_INTERVAL_PACKETS: u64 = 1024;
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

pub(crate) struct RotatingSavefile {
    base_path: PathBuf,
    rotation: Option<PcapRotationPolicy>,
    current_segment: u64,
    current_bytes: u64,
    rotate_pending: bool,
    segment_paths: VecDeque<PathBuf>,
    savefile: pcap::Savefile,
}

impl RotatingSavefile {
    pub(crate) fn open(
        cap: &mut CaptureSource,
        output: &config::OutputConfig,
    ) -> Result<Option<Self>, pcap::Error> {
        let Some(base_path) = output.write_pcap.as_deref() else {
            return Ok(None);
        };
        let rotation = PcapRotationPolicy::from_output(output);
        let writer = if let Some(rotation) = rotation {
            let existing_segments = Self::collect_existing_segments(base_path);
            let first_segment = existing_segments
                .last()
                .map(|(segment, _)| segment.saturating_add(1))
                .unwrap_or(1);
            let path = Self::segment_path(base_path, first_segment);
            let savefile = cap.savefile(&path, true)?;
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
            writer
        } else {
            let savefile = cap.savefile(base_path, false)?;
            Self {
                base_path: base_path.to_path_buf(),
                rotation,
                current_segment: 0,
                current_bytes: 0,
                rotate_pending: false,
                segment_paths: VecDeque::new(),
                savefile,
            }
        };
        Ok(Some(writer))
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
        self.savefile = cap.savefile(&next_path, true)?;
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
            if !entry
                .file_type()
                .is_ok_and(|kind| kind.is_file() || kind.is_symlink())
            {
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
        #[cfg(any(target_os = "macos", windows))]
        let file_name = file_name.to_ascii_lowercase();
        let stem = base_path
            .file_stem()
            .or_else(|| base_path.file_name())
            .unwrap_or_else(|| OsStr::new("capture"))
            .to_string_lossy();

        #[cfg(any(target_os = "macos", windows))]
        let stem = stem.to_ascii_lowercase();
        let with_stem_prefix = format!("{}.", stem);

        let index_str = if let Some(ext) = base_path.extension() {
            let ext_suffix = format!(".{}", ext.to_string_lossy());
            #[cfg(any(target_os = "macos", windows))]
            let ext_suffix = ext_suffix.to_ascii_lowercase();
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

pub(crate) fn write_packet_to_savefile(
    savefile: &mut Option<&mut RotatingSavefile>,
    packet: &pcap::Packet<'_>,
    packet_count: u64,
) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.write_packet(packet, packet_count)?;
    }
    Ok(())
}

pub(crate) fn maybe_rotate_savefile(
    cap: &mut CaptureSource,
    savefile: &mut Option<&mut RotatingSavefile>,
) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.rotate_if_needed(cap)?;
    }
    Ok(())
}

pub(crate) fn flush_savefile(
    savefile: &mut Option<&mut RotatingSavefile>,
) -> Result<(), pcap::Error> {
    if let Some(file) = savefile.as_mut() {
        file.flush()?;
    }
    Ok(())
}

pub(crate) fn validate_segment_paths(
    base: &Path,
    reads: &[(&str, &Path)],
    outputs: &[(&str, &Path)],
) -> Result<(), String> {
    let segments = RotatingSavefile::collect_existing_segments(base);
    let next_index = segments
        .last()
        .map_or(1, |(index, _)| index.saturating_add(1));
    let next_path = RotatingSavefile::segment_path(base, next_index);
    for (name, path) in reads.iter().chain(
        outputs
            .iter()
            .filter(|(name, _)| *name != "output.write_pcap"),
    ) {
        let resolved = output_paths::resolved(path)?;
        let in_namespace = |candidate: &Path| -> Result<bool, String> {
            Ok(output_paths::same_parent(base, candidate)?
                && RotatingSavefile::parse_segment_index(base, candidate).is_some())
        };
        if in_namespace(path)? || in_namespace(&resolved)? {
            return Err(format!(
                "{name} overlaps the rotated PCAP filename namespace"
            ));
        }
        output_paths::validate(
            &[(*name, *path)],
            &[("next rotated PCAP segment", next_path.as_path())],
        )?;
        for (_, segment) in &segments {
            output_paths::validate(
                &[(*name, *path)],
                &[("rotated PCAP segment", segment.as_path())],
            )?;
        }
    }
    Ok(())
}
