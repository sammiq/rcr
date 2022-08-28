use anyhow::{anyhow, Result};
use log::{debug, trace, warn};
use sha1::Digest;
use std::ffi::OsString;
use std::fs::File;
use std::io::{copy, BufReader, Write};
use std::path::{Path, PathBuf};

pub fn rename_file(in_file: &Path, file_name: &str) {
    //all i wanted to do was copy a path but and replace the file name part,
    //caused me far more problems than i thought it should because PathBuf has
    //no copy trait
    let out_name: OsString = file_name.to_string().into(); //&str -> copy to String -> OString
    let out_path: OsString = in_file.as_os_str().to_os_string(); //PathBuf -> &OStr -> copy to OString
    let mut out_file: PathBuf = out_path.into(); //OString -> PathBuf - moves outpath
    out_file.set_file_name(out_name); // replace filename portion - borrow outname
    match std::fs::rename(&in_file, &out_file) {
        Ok(_) => debug!("'{}' renamed to '{}'", in_file.display(), out_file.display()),
        Err(err) => warn!("could not rename '{}' to '{}' - {err}", in_file.display(), out_file.display()),
    }
}

pub fn calc_md5_for_file(file: &Path) -> Result<String> {
    let mut hasher = md5::Md5::new();
    calc_hash_for_file(file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(base16ct::lower::encode_string(&hash))
}

pub fn calc_sha1_for_file(file: &Path) -> Result<String> {
    let mut hasher = sha1::Sha1::new();
    calc_hash_for_file(file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(base16ct::lower::encode_string(&hash))
}

pub fn calc_crc_for_file(_: &Path) -> Result<String> {
    //FIXME do the crc
    Err(anyhow!("not implemented"))
}

fn calc_hash_for_file<T: ?Sized>(file: &Path, hasher: &mut T) -> Result<()>
where
    T: Write,
{
    let f = File::open(file)?;
    let mut reader = BufReader::new(f);
    trace!("start hashing {}", file.display());
    let _n = copy(&mut reader, hasher)?;
    trace!("end hashing {}", file.display());
    Ok(())
}
