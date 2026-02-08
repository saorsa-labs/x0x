use std::path::Path;

const SNAPSHOT_EXT: &str = "snapshot";
const SNAPSHOT_TIMESTAMP_WIDTH: usize = 20;

pub(crate) fn snapshot_file_name(timestamp_millis: u128) -> String {
    format!("{:020}.{}", timestamp_millis, SNAPSHOT_EXT)
}

pub(crate) fn snapshot_timestamp_from_path(path: &Path) -> Option<u128> {
    let extension = path.extension().and_then(|ext| ext.to_str())?;
    if extension != SNAPSHOT_EXT {
        return None;
    }

    let stem = path.file_stem().and_then(|stem| stem.to_str())?;
    if stem.len() != SNAPSHOT_TIMESTAMP_WIDTH || !stem.as_bytes().iter().all(u8::is_ascii_digit) {
        return None;
    }

    stem.parse::<u128>().ok()
}

#[cfg(test)]
mod tests {
    use super::{snapshot_file_name, snapshot_timestamp_from_path};
    use std::path::Path;

    #[test]
    fn snapshot_filename_round_trip_is_stable() {
        let ts = 42_u128;
        let name = snapshot_file_name(ts);
        assert_eq!(name, "00000000000000000042.snapshot");
        assert_eq!(snapshot_timestamp_from_path(Path::new(&name)), Some(ts));
    }

    #[test]
    fn snapshot_filename_parser_rejects_malformed_paths() {
        assert_eq!(
            snapshot_timestamp_from_path(Path::new("short.snapshot")),
            None
        );
        assert_eq!(snapshot_timestamp_from_path(Path::new("42.snapshot")), None);
        assert_eq!(
            snapshot_timestamp_from_path(Path::new("00000000000000000042.tmp")),
            None
        );
    }
}
