use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use log::{debug, info, warn};
use std::fs::File;
use std::io::BufReader;

pub fn rename_file_if_possible(in_file: &Utf8Path, file_name: &str) -> Result<Utf8PathBuf> {
    let mut out_file = Utf8PathBuf::from(in_file);
    out_file.set_file_name(file_name);
    std::fs::rename(in_file, &out_file)?;
    Ok(out_file)
}

pub fn reader_for_filename(file: &Utf8Path) -> Result<BufReader<File>> {
    let f = File::open(file)?;
    Ok(BufReader::new(f))
}

pub fn rename_preserving_extension(file_path: &Utf8Path, new_name: &str) -> Result<()> {
    let file_name = file_path.file_name().context("file path should always have a file name")?;
    let new_file_name = match file_path.extension() {
        Some(ext) => new_name.to_string() + "." + ext,
        None => new_name.to_string(),
    };
    if file_name != new_file_name {
        debug!("renaming {file_path} to {new_file_name}");
        match rename_file_if_possible(file_path, &new_file_name) {
            Ok(new_path) => info!("{new_path} (renamed from {file_path})"),
            Err(err) => warn!("could not rename '{file_path}' to '{new_file_name}' - {err}"),
        }
    }
    Ok(())
}
