use std::sync::Arc;



use super::request_log::{SpoolFileRef, SpoolRequestLog, REQUEST_LOG_UNARMED_MARKER};

pub(crate) fn initialize_spool(spool_dir: &std::path::Path, max_entry_bytes: u64) -> Result<u64, String> {
    std::fs::create_dir_all(spool_dir).map_err(|error| error.to_string())?;
    let mut directory_changed = false;
    for entry in std::fs::read_dir(spool_dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if file_name.starts_with(".tmp-") || file_name.starts_with(".admission-tmp-") {
            if entry
                .metadata()
                .map_err(|error| error.to_string())?
                .is_file()
            {
                std::fs::remove_file(&path).map_err(|error| error.to_string())?;
                directory_changed = true;
            }
            continue;
        }
        let Some(stable_name) = file_name.strip_prefix(".admission-") else {
            continue;
        };
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() {
            continue;
        }
        if metadata.len() > max_entry_bytes {
            return Err(format!(
                "request-log admission marker {} exceeds entry quota",
                path.display()
            ));
        }
        let encoded = std::fs::read(&path).map_err(|error| error.to_string())?;
        if encoded == REQUEST_LOG_UNARMED_MARKER {
            std::fs::remove_file(&path).map_err(|error| error.to_string())?;
            directory_changed = true;
            continue;
        }
        serde_json::from_slice::<SpoolRequestLog>(&encoded).map_err(|error| {
            format!(
                "request-log admission marker {} is not recoverable: {error}",
                path.display()
            )
        })?;
        let final_path = spool_dir.join(format!("{stable_name}.json"));
        if final_path.exists() {
            std::fs::remove_file(&path).map_err(|error| error.to_string())?;
        } else {
            std::fs::rename(&path, &final_path).map_err(|error| error.to_string())?;
        }
        directory_changed = true;
    }
    if directory_changed {
        sync_directory(spool_dir)?;
    }

    let mut bytes = 0_u64;
    for entry in std::fs::read_dir(spool_dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if metadata.is_file() {
            bytes = bytes.saturating_add(metadata.len());
        }
    }
    Ok(bytes)
}

pub(crate) fn write_admission_marker(
    spool_dir: &std::path::Path,
    marker: &std::path::Path,
) -> Result<(), String> {
    use std::io::Write;
    std::fs::create_dir_all(spool_dir).map_err(|error| error.to_string())?;
    let nonce = uuid::Uuid::new_v4().simple();
    let tmp = spool_dir.join(format!(".admission-tmp-{nonce}"));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|error| error.to_string())?;
        file.write_all(REQUEST_LOG_UNARMED_MARKER)
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        std::fs::rename(&tmp, &marker).map_err(|error| error.to_string())?;
        sync_directory(spool_dir)?;
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&marker);
        return Err(error);
    }
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn sync_directory(directory: &std::path::Path) -> Result<(), String> {
    std::fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
pub(crate) fn sync_directory(directory: &std::path::Path) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

pub(crate) async fn write_spool_file(
    spool_dir: &std::path::Path,
    tmp: &std::path::Path,
    path: &std::path::Path,
    encoded: Arc<[u8]>,
) -> Result<(), String> {
    let spool_dir = spool_dir.to_path_buf();
    let tmp = tmp.to_path_buf();
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        std::fs::create_dir_all(&spool_dir).map_err(|error| error.to_string())?;
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|error| error.to_string())?;
            file.write_all(&encoded)
                .map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            std::fs::rename(&tmp, &path).map_err(|error| error.to_string())?;
            sync_directory(&spool_dir)?;
            Ok::<(), String>(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    })
    .await
    .map_err(|error| error.to_string())?
}

pub(crate) async fn load_spool_batch(
    spool_dir: &std::path::Path,
    buffered: Vec<SpoolFileRef>,
    max_entries: usize,
    max_entry_bytes: u64,
) -> Result<Vec<(SpoolFileRef, SpoolRequestLog)>, String> {
    let mut paths = buffered
        .into_iter()
        .map(|entry| entry.path)
        .collect::<std::collections::BTreeSet<_>>();
    let mut directory = tokio::fs::read_dir(spool_dir)
        .await
        .map_err(|error| error.to_string())?;
    while paths.len() < max_entries {
        let Some(entry) = directory
            .next_entry()
            .await
            .map_err(|error| error.to_string())?
        else {
            break;
        };
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.insert(path);
        }
    }
    let mut entries = Vec::with_capacity(paths.len().min(max_entries));
    for path in paths.into_iter().take(max_entries) {
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("read {} metadata: {error}", path.display())),
        };
        if metadata.len() > max_entry_bytes {
            return Err(format!(
                "spool entry {} exceeds entry quota",
                path.display()
            ));
        }
        let raw = tokio::fs::read(&path)
            .await
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        let log = serde_json::from_slice::<SpoolRequestLog>(&raw)
            .map_err(|error| format!("decode {}: {error}", path.display()))?;
        entries.push((
            SpoolFileRef {
                path,
                bytes: metadata.len(),
            },
            log,
        ));
    }
    Ok(entries)
}
