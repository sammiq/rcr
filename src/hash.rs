use crate::extensions::*;

use anyhow::{Context, Result};
use camino::Utf8Path;
use clap::ValueEnum;
use digest::Digest;
use log::{debug, warn};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{copy, Read, Write};

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

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
pub enum MatchMethod {
    Sha256,
    Sha1,
    Md5,
}

impl Display for MatchMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchMethod::Sha256 => write!(f, "sha256"),
            MatchMethod::Sha1 => write!(f, "sha1"),
            MatchMethod::Md5 => write!(f, "md5"),
        }
    }
}

pub fn hash_file_with_method<R: Read + ?Sized>(reader: &mut R, method: MatchMethod) -> Result<String> {
    match method {
        MatchMethod::Sha256 => calc_sha256_for_reader(reader),
        MatchMethod::Sha1 => calc_sha1_for_reader(reader),
        MatchMethod::Md5 => calc_md5_for_reader(reader),
    }
}

pub fn hash_zip_file_contents(file: &Utf8Path, method: MatchMethod) -> Result<BTreeMap<String, String>> {
    let f = File::open(file).with_context(|| format!("could not open file '{file}'"))?;
    let mut zip = zip::ZipArchive::new(f).with_context(|| format!("could not open '{file}' as a zip file"))?;
    let mut found_files = BTreeMap::new();
    for i in 0..zip.len() {
        let mut inner_file = zip.by_index(i)?; //fix error
        if inner_file.is_file() {
            hash_file_with_method(&mut inner_file, method)
                .map(|hash| {
                    debug!("hash for {} in zip {} is {}", inner_file.name(), file, hash);
                    found_files.insert(inner_file.name().to_string(), hash);
                })
                .if_err(|error| warn!("could not process '{}' in zip file '{file}', error was '{error}'", inner_file.name()));
        }
    }
    Ok(found_files)
}
