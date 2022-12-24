use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::fs::File;
use std::io::{copy, BufReader, Read, Write};

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
