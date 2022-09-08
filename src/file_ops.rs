use anyhow::{anyhow, Result};
use log::{debug, trace, warn};
use sha1::Digest;
use std::fs::File;
use std::io::{copy, BufReader, Write};
use camino::{Utf8Path, Utf8PathBuf};

pub fn rename_file_if_possible(in_file: &Utf8Path, file_name: &str) {
    let mut out_file = Utf8PathBuf::from(in_file);
    out_file.set_file_name(file_name);
    match std::fs::rename(&in_file, &out_file) {
        Ok(_) => debug!("'{}' renamed to '{}'", in_file, out_file),
        Err(err) => warn!("could not rename '{}' to '{}' - {err}", in_file, out_file),
    }
}

pub fn calc_md5_for_file(file: &Utf8Path) -> Result<String> {
    let mut hasher = md5::Md5::new();
    calc_hash_for_file(file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(base16ct::lower::encode_string(&hash))
}

pub fn calc_sha1_for_file(file: &Utf8Path) -> Result<String> {
    let mut hasher = sha1::Sha1::new();
    calc_hash_for_file(file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(base16ct::lower::encode_string(&hash))
}

pub fn calc_crc_for_file(_: &Utf8Path) -> Result<String> {
    //FIXME do the crc
    Err(anyhow!("not implemented"))
}

fn calc_hash_for_file<T: ?Sized>(file: &Utf8Path, hasher: &mut T) -> Result<()>
where
    T: Write,
{
    let f = File::open(file)?;
    let mut reader = BufReader::new(f);
    trace!("start hashing {}", file);
    let _n = copy(&mut reader, hasher)?;
    trace!("end hashing {}", file);
    Ok(())
}
