mod file_ops;

use crate::file_ops::{calc_crc_for_file, calc_md5_for_file, calc_sha1_for_file, rename_file};
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum, ValueHint};
use log::{debug, info, trace, warn};
use roxmltree::{Document, Node};
use std::collections::HashSet;
use camino::{Utf8Path, Utf8PathBuf};


#[derive(Debug, Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// name of the dat file to use as reference
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    dat_file: Utf8PathBuf,

    /// verbose mode, add more of these for more information
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// checks files against dat file
    Check(CheckArgs),
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// method to use for matching reference entries
    #[clap(short, long, value_enum, default_value_t = MatchMethod::Sha1)]
    method: MatchMethod,

    /// multiple match mode for merged sets
    #[clap(short, long)]
    multiple: bool,

    /// rename mismatched files to reference filename
    #[clap(short, long)]
    rename: bool,

    /// list of files to check against reference dat file
    #[clap(required = true, value_parser, value_hint = ValueHint::FilePath)]
    files: Vec<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum, strum::Display)]
enum MatchMethod {
    Sha1,
    Md5,
    Crc,
}

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new().init().unwrap();

    let args = Cli::parse();
    set_logging_level(args.verbose);
    debug!("raw args: {:?}", args);

    trace!("reading dat file {}", args.dat_file);
    //read in the xml to buffer, roxmltree is a bit fiddly with ownership
    let df_buffer = std::fs::read_to_string(&args.dat_file).with_context(|| "Unable to read reference dat file - {err}")?;
    let df_xml = Document::parse(df_buffer.as_str()).with_context(|| "Unable to parse reference dat file - {err}")?;
    info!("dat file {} read successfully", args.dat_file);

    //debug!("raw xml: {:?}", df_xml);
    match args.command {
        Commands::Check(check_args) => {
            //windows will not glob externally, so we need to do it here
            let input_files : Vec<Utf8PathBuf> = check_args.files.iter().flat_map(|f| expand_path_ignore_invalid(f)).collect();

            for file_path in input_files {
                let hash_result = hash_candidate_file(check_args.method, &file_path);
                match hash_result {
                    Ok(hash_string) => {
                        let found = check_file(&df_xml, &check_args, &file_path, &hash_string);
                        debug!("found nodes by hash {:?}", found);
                    }
                    Err(err) => warn!("could not hash '{}', file will be skipped - {err}", file_path),
                }
            }
        }
    }
    Ok(())
}

fn check_file<'a>(df_xml: &'a Document, check_args: &CheckArgs, file_path: &Utf8Path, hash: &str) -> Vec<Node<'a, 'a>> {
    let file_name = file_path.file_name().unwrap(); // this should never fail in this circumstance
    debug!("hash for '{file_name}' = {hash}");
    let found_nodes = find_nodes_by_hash_attribute(df_xml, check_args.method, hash, check_args.multiple);
    if found_nodes.is_empty() {
        println!("[MISS] {hash} {file_name} - unknown, no match");
    } else {
        let mut names = HashSet::new();

        for node in &found_nodes {
            //FIXME verify its a "rom" node?
            let node_name = node.attribute("name").unwrap_or(""); //this shouldn't happen but don't error out if it does
            names.insert(node_name);

            if node_name == file_name {
                println!("[ OK ] {hash} {file_name}");
            } else {
                println!("[WARN] {hash} {file_name}  - misnamed, should be {}", node_name);
            }
        }

        //only consider rename if a single name found
        if check_args.rename && names.len() == 1 {
            let new_name = names.iter().next().unwrap(); // should never fail as we checked length
            if file_name != *new_name {
                debug!("renaming {} to {}", file_name, new_name);
                rename_file(&file_path.as_std_path(), new_name);
            }
        }
    }
    found_nodes
}

fn expand_path_ignore_invalid(pattern: &str) -> Vec<Utf8PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => paths
            .filter_map(Result::ok)
            .map(| f| Utf8PathBuf::from_path_buf(f).unwrap())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn set_logging_level(verbose: u8) {
    //set the logger level depending on verbose flags (they stack)
    let max_level = match verbose {
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        3..=u8::MAX => log::LevelFilter::Trace,
        _ => log::LevelFilter::Warn,
    };
    log::set_max_level(max_level);
    info!("Log Level set to {}", max_level);
}

fn hash_candidate_file(method: MatchMethod, file: &Utf8Path) -> Result<String> {
    match method {
        MatchMethod::Sha1 => calc_sha1_for_file(file.as_std_path()),
        MatchMethod::Md5 => calc_md5_for_file(file.as_std_path()),
        MatchMethod::Crc => calc_crc_for_file(file.as_std_path()),
    }
}

fn find_nodes_by_hash_attribute<'a>(df_xml: &'a Document, method: MatchMethod, hash_string: &str, multiple: bool) -> Vec<Node<'a, 'a>> {
    let m = method.to_string().to_ascii_lowercase();
    debug!("looking up '{}' using method '{}'", hash_string, m);
    if multiple {
        df_xml
            .descendants()
            .filter(|n| n.attribute(&*m).map(|s| s.to_string().to_ascii_lowercase()) == Some(hash_string.to_ascii_lowercase()))
            .collect()
    } else {
        let mut vec = Vec::new();
        df_xml
            .descendants()
            .find(|n| n.attribute(&*m).map(|s| s.to_string().to_ascii_lowercase()) == Some(hash_string.to_ascii_lowercase()))
            .iter()
            .for_each(|a| vec.push(*a)); //slightly convoluted because iter() returns a ref instead
        vec
    }
}
