use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::fs::File;
use std::io::{copy, BufReader, Read, Write};
#[cfg(windows)]
use std::os::windows::prelude::*;

pub fn move_file_if_possible(in_file: &Utf8Path, out_path: &Utf8Path) -> Result<Utf8PathBuf> {
    let file_name = in_file.file_name().context("expected a filename to be passed in argument")?;
    let mut out_file = out_path.to_path_buf();
    out_file.push(file_name);
    std::fs::rename(in_file, &out_file)?;
    Ok(out_file)
}

pub fn rename_file_if_possible(in_file: &Utf8Path, file_name: &str) -> Result<Utf8PathBuf> {
    let mut out_file = Utf8PathBuf::from(in_file);
    out_file.set_file_name(file_name);
    std::fs::rename(in_file, &out_file)?;
    Ok(out_file)
}

pub fn calc_md5_for_reader<R: Read + ?Sized>(reader: &mut R) -> Result<String> {
    calc_hash_for_digest::<Md5, R>(reader)
}

pub fn calc_sha1_for_reader<R: Read + ?Sized>(reader: &mut R) -> Result<String> {
    calc_hash_for_digest::<Sha1, R>(reader)
}

pub fn calc_sha256_for_reader<R: Read + ?Sized>(reader: &mut R) -> Result<String> {
    calc_hash_for_digest::<Sha256, R>(reader)
}

pub fn calc_hash_for_digest<D: Digest + Write, R: Read + ?Sized>(reader: &mut R) -> Result<String> {
    let mut hasher = D::new();
    copy(reader, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(base16ct::lower::encode_string(&hash))
}

pub fn reader_for_filename(file: &Utf8Path) -> Result<BufReader<File>> {
    let f = File::open(file)?;
    Ok(BufReader::new(f))
}

#[cfg(windows)]
pub fn is_hidden_file(file: &Utf8Path) -> bool {
    file.metadata()
        .map(|metadata| metadata.file_attributes() & 0x00000002 != 0)
        .unwrap_or(false)
}

#[cfg(not(windows))]
pub fn is_hidden_file(file: &Utf8Path) -> bool {
    file.file_name().map(|filename| filename.starts_with('.')).unwrap_or(false)
}

pub fn match_filename(file_name: &str, rom_name: &str, ignore_suffix: bool) -> bool {
    if ignore_suffix {
        let f = Utf8Path::new(file_name).with_extension("");
        let r = Utf8Path::new(rom_name).with_extension("");

        f == r
    } else {
        rom_name == file_name
    }
}
