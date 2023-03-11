mod check;
mod dat_ops;
mod dat_to_db;
mod db;
mod extensions;
mod file_ops;
mod hash;

use crate::check::*;
use crate::dat_ops::*;
use crate::dat_to_db::*;
use crate::db::*;
use crate::file_ops::*;
use crate::hash::*;

use std::collections::{BTreeSet, VecDeque};
use std::env;
use std::fmt::format;

use crate::extensions::ResultExt;
use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand, ValueHint};
use log::{debug, info, warn};
use rusqlite::Connection;

#[derive(Debug, Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// name for the database
    #[clap(short, long, default_value = "rcr.sqlite3", env = "RCR_DB_NAME")]
    db_name: String,

    /// verbose mode, add more of these for more information
    #[clap(short, long, action = clap::ArgAction::Count, env = "RCR_VERBOSE")]
    verbose: u8,

    /// number of threads to use for processing, may increase performance
    /// (note: depends on storage bandwidth, more may be slower than fewer)
    #[clap(short, long, default_value_t = 1, verbatim_doc_comment, env = "RCR_WORKERS")]
    workers: u8,

    /// command to execute
    #[clap(subcommand)]
    command: CliCommands,
}

#[derive(Clone, Debug, Subcommand)]
enum CliCommands {
    /// Scan all files in directory, clear any existing database
    Build(BuildArgs),
    /// Check given files in directory against a dat-file, without adding them to a database
    Check(CheckArgs),
    /// Scan for changes in directory, adding new files and removing old files from the database
    Scan(ScanArgs),
    /// List files in the database
    List,
    /// Upgrade the dat-file reference, re-matching files against the dat-file
    Upgrade(UpgradeArgs),
    /// Verify the files in the directory match the database
    Verify,
}

#[derive(Clone, Debug, Args)]
struct BuildArgs {
    /// Name of the dat-file to use as reference
    #[clap(short, long, value_parser, value_hint = ValueHint::FilePath)]
    dat_file: Utf8PathBuf,

    /// Comma seperated list of suffixes to exclude when scanning
    #[clap(short, long, value_delimiter = ',', env = "RCR_EXCLUDE")]
    exclude: Vec<String>,

    /// Comma seperated list of suffixes to include when scanning, defaults to all files
    #[clap(short, long, value_delimiter = ',', env = "RCR_INCLUDE")]
    include: Vec<String>,

    /// Method to use for matching dat-file entries, ignored if no hashes of this type
    #[clap(short, long, value_enum, default_value_t = MatchMethod::Sha1, env = "RCR_METHOD")]
    method: MatchMethod,

    /// Recursively process sub-directories
    #[clap(short = 'R', long, env = "RCR_RECURSIVE")]
    recursive: bool,

    /// Rename mismatched files to dat-file entry, if unambiguous
    #[clap(short, long, env = "RCR_RENAME")]
    rename: bool,
}

#[derive(Clone, Debug, Args)]
struct ScanArgs {
    /// comma seperated list of suffixes to exclude when scanning
    #[clap(short, long, value_delimiter = ',', verbatim_doc_comment, env = "RCR_EXCLUDE")]
    exclude: Vec<String>,

    /// comma seperated list of suffixes to include when scanning
    #[clap(short, long, value_delimiter = ',', verbatim_doc_comment, env = "RCR_INCLUDE")]
    include: Vec<String>,

    /// Re-scan all files in directory, clear entries and recalculate hashes for all files
    #[clap(short, long, env = "RCR_FULL_SCAN")]
    full: bool,

    /// rename mismatched files to reference filename if unambiguous
    #[clap(short, long, env = "RCR_RENAME")]
    rename: bool,
}

#[derive(Clone, Debug, Args)]
struct UpgradeArgs {
    /// name of the dat file to use as reference, replacing previous reference
    #[clap(short, long, value_parser, value_hint = ValueHint::FilePath)]
    dat_file: Utf8PathBuf,

    /// rename mismatched files to reference filename if unambiguous
    #[clap(short, long, env = "RCR_RENAME")]
    rename: bool,
}

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .init()
        .expect("should be able to initialize the logger");

    //load .env file from current directory only
    if let Ok(mut path) = env::current_dir() {
        path.push(".env");
        if path.is_file() {
            dotenvy::from_path(path).context("Unable to read .env file (possibly malformed input)")?;
        }
    }

    //wild takes care of globbing on windows instead of manually doing it ourselves
    let args = Cli::parse_from(wild::args_os());
    set_logging_level(args.verbose);
    debug!("raw args: {:?}", args);

    rayon::ThreadPoolBuilder::new()
        .num_threads(args.workers as usize)
        .build_global()
        .expect("should be able to initialize the thread pool");
    info!("using {} threads for processing", args.workers);

    match args.command {
        CliCommands::Build(ref build_args) => run_build(&args.db_name, build_args),
        CliCommands::Check(ref check_args) => run_check(check_args),
        // error if no database
        //scan all new files in directory and add to db
        CliCommands::Scan(_) => Ok(()),
        // error if no database
        // list out matching and non-matching files
        CliCommands::List => Ok(()),
        // error if no database
        // clear existing dat database
        // update new dat database
        //reprocess files and rename if required
        CliCommands::Upgrade(_) => Ok(()),
        // error if no database
        // loop thru files and verify unchanged from db
        CliCommands::Verify => Ok(()),
    }
}

fn run_build(db_name: &str, build_args: &BuildArgs) -> Result<()> {
    //we need to read out method as it can change if not found in dat-file
    let (connection, method) = read_dat_to_db(db_name, &build_args.dat_file, build_args.method)?;
    //we now can operate from the database and start processing files
    let mut exclusions = BTreeSet::new();
    exclusions.extend(build_args.exclude.iter().cloned());

    let mut inclusions = BTreeSet::new();
    inclusions.extend(build_args.include.iter().cloned());

    let mut dir_queue = VecDeque::new();
    dir_queue.push_back(env::current_dir().context("cannot get current directory")?);

    while let Some(directory) = dir_queue.pop_front() {
        Utf8Path::from_path(directory.as_path())
            .context("cannot process current directory")?
            .read_dir_utf8()
            .context("cannot read current directory")?
            .for_each(|f| match f {
                Ok(de) => {
                    let path = de.path();
                    if path.is_dir() {
                        if build_args.recursive {
                            debug!("{path} is a directory, queueing for processing");
                            dir_queue.push_back(directory.to_path_buf())
                        } else {
                            debug!("{path} is a directory, skipping");
                        }
                        return;
                    }

                    process_file(db_name, &connection, method, &exclusions, &inclusions, path)
                        .if_err(|e| warn!("unable to process {path}, error was {e}"));
                }
                Err(err) => warn!("error while enumerating directory. Error was {}", err),
            });
    }
    Ok(())
}

fn process_file(
    db_name: &str,
    connection: &Connection,
    method: MatchMethod,
    exclusions: &BTreeSet<String>,
    inclusions: &BTreeSet<String>,
    file_path: &Utf8Path,
) -> Result<()> {
    if !file_path.is_file() {
        warn!("{file_path} is not a regular file, skipping");
        return Ok(());
    }

    let file_name = file_path
        .file_name()
        .context("expect a file to have a filename that is accessible")?;

    if file_name.starts_with('.') {
        debug!("{file_path} is a hidden entry (dotfile or the like), skipping");
        return Ok(());
    }

    if file_name == db_name {
        debug!("{file_path} is the database in use, skipping");
        return Ok(());
    }

    if file_path.extension().map(|ext| exclusions.contains(ext)).unwrap_or(false) {
        info!("{file_path} has an extension that is excluded, skipping");
        return Ok(());
    }
    if !inclusions.is_empty() && file_path.extension().map(|inc| inclusions.contains(inc)).unwrap_or(false) {
        info!("{file_path} has an extension that is not included, skipping");
        return Ok(());
    }

    let hash = reader_for_filename(file_path)
        .and_then(|mut reader| hash_file_with_method(&mut reader, method))
        .with_context(|| format!("unable to hash file {file_path}"))?;

    debug!("{} {}", file_name, hash);
    let hash_matches = find_references_by_hash(connection, &hash).context("unable to access database while searching for hash")?;

    debug!("{} {} {:?}", file_name, hash, hash_matches);
    match hash_matches.len() {
        0 => {
            debug!("{} {} found no entry in database (using hash), checking name", hash, file_name);
            let name_matches =
                find_references_by_name(connection, file_name).context("unable to access database while searching for name")?;
            match name_matches.len() {
                //no names match
                0 => println!("[MISS] {} {} - unknown, no match", hash, file_name),
                _ => {
                    //we should check the size of the file, vs the size of the expected file, could be an overdump
                    println!("[BAD ] {} {} - incorrect hash, should be:", hash, file_name);
                    name_matches.iter().for_each(|name_match| {
                        println!("       {} {} (part of {})", name_match.file_hash, name_match.file_name, name_match.game_name)
                    });
                }
            };
            add_file_entry(connection, &hash, file_name, None).context("unable to access database while adding entry")?;
        }
        1 => {
            debug!("{} {} found unambiguous entry in database (using hash)", hash, file_name);
            let entry = &hash_matches[0];
            if entry.file_name == file_name {
                println!("[ OK ] {} {}", hash, file_name);
            } else {
                //rename if required or report name issue
                println!("[WARN] {} {} - incorrect name, should be:", hash, file_name);
                println!("       {} {} (part of {})", entry.file_hash, entry.file_name, entry.game_name);
            }
            add_file_entry(connection, &hash, file_name, Some(entry.id)).context("unable to access database while adding entry")?;
        }
        _ => {
            debug!("{} {} found ambiguous entries in database (using hash), checking name", hash, file_name);
            let name_matches: Vec<&ReferenceEntry> = hash_matches.iter().filter(|&entry| entry.file_name == file_name).collect();
            match name_matches.len() {
                0 => {
                    println!("[WARN] {} {} - incorrect name, could be one of:", hash, file_name);
                    hash_matches.iter().for_each(|hash_match| {
                        println!("       {} {} (part of {})", hash_match.file_hash, hash_match.file_name, hash_match.game_name)
                    });
                    //need to add to ambiguous match table
                }
                1 => {
                    println!("[ OK ] {} {}", hash, file_name);
                    add_file_entry(connection, &hash, file_name, Some(name_matches[0].id))
                        .context("unable to access database while adding entry")?;
                }
                _ => {
                    println!("[WARN] {} {} - ambiguous name, could be one of:", hash, file_name);
                    hash_matches.iter().for_each(|hash_match| {
                        println!("       {} {} (part of {})", hash_match.file_hash, hash_match.file_name, hash_match.game_name)
                    });
                    //need to add to ambiguous match table
                }
            }
        }
    }
    Ok(())
}

fn set_logging_level(verbose: u8) {
    //set the logger level depending on verbose flags (they stack)
    let max_level = match verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    log::set_max_level(max_level);
    info!("Log Level set to {}", max_level);
}
