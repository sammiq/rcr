use crate::dat_ops::*;
use crate::file_ops::*;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, ValueEnum, ValueHint};
use log::{debug, info, trace, warn};
use roxmltree::{Document, Node};

//simple macro to conditionally println
#[macro_export]
macro_rules! println_if {
    ($cond:expr, $($arg:tt)*) => {
        if $cond {
            println!($($arg)*);
        }
    };
}

#[derive(Debug, Args)]
pub struct MatchOptions {
    /// count any matches in a zip file as a match, otherwise
    /// the file count must match for a partial match
    #[clap(short, long, verbatim_doc_comment, env = "RCR_ANY_CONTENTS")]
    pub any_contents: bool,

    /// fast match mode for single rom games,
    /// may show incorrect names if multiple identical hashes
    #[clap(short('F'), long, verbatim_doc_comment, env = "RCR_FAST")]
    pub fast: bool,

    /// ignore the suffix when checking for name match
    #[clap(short, long, env = "RCR_IGNORE_SUFFIX")]
    pub ignore_suffix: bool,

    /// default method to use for matching reference entries
    #[clap(short('M'), long, value_enum, default_value_t = MatchMethod::Sha1, verbatim_doc_comment, env = "RCR_METHOD")]
    pub method: MatchMethod,
}

#[derive(Debug, Args)]
pub struct OutputOptions {
    /// filter for printing information on found/matched items
    #[clap(short, long, value_enum, default_value_t = OutputFilter::All, env = "RCR_FOUND")]
    pub found: OutputFilter,

    /// filter for printing information on missing/unknown items
    #[clap(short, long, value_enum, default_value_t = OutputFilter::All, env = "RCR_MISSING")]
    pub missing: OutputFilter,

    /// filter for printing information on misnamed, partial and ambiguous items
    #[clap(short, long, value_enum, default_value_t = OutputFilter::All, env = "RCR_WARNING")]
    pub warning: OutputFilter,

    /// rename mismatched files to reference filename if unambiguous
    #[clap(short, long, env = "RCR_RENAME")]
    pub rename: bool,

    /// sort files into directories based on match status
    #[clap(short, long, value_enum, default_value_t = SortOption::None, env = "RCR_SORT")]
    pub sort: SortOption,

    /// base directory to use when sorting files
    #[clap(short('S'), long, value_parser, value_hint = ValueHint::DirPath, default_value = ".", env = "RCR_SORTDIR")]
    pub sort_dir: Utf8PathBuf,
}

#[derive(Debug, Args)]
pub struct ProcessingOptions {
    #[clap(flatten)]
    pub matches: MatchOptions,

    #[clap(flatten)]
    pub output: OutputOptions,
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
pub enum OutputFilter {
    Files,
    Sets,
    All,
    None,
}

impl OutputFilter {
    pub fn output_files(&self) -> bool {
        *self == OutputFilter::Files || *self == OutputFilter::All
    }

    pub fn output_sets(&self) -> bool {
        *self == OutputFilter::Sets || *self == OutputFilter::All
    }
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
pub enum MatchMethod {
    Sha256,
    Sha1,
    Md5,
}

impl MatchMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchMethod::Sha256 => "sha256",
            MatchMethod::Sha1 => "sha1",
            MatchMethod::Md5 => "md5",
        }
    }

    pub fn hash_data<R: std::io::Read + ?Sized>(&self, reader: &mut R) -> Result<String> {
        match self {
            MatchMethod::Sha256 => calc_sha256_for_reader(reader),
            MatchMethod::Sha1 => calc_sha1_for_reader(reader),
            MatchMethod::Md5 => calc_md5_for_reader(reader),
        }
    }

    #[cfg(feature = "memmap2")]
    pub fn hash_data_buffer(&self, buffer: &[u8]) -> Result<String> {
        match self {
            MatchMethod::Sha256 => calc_sha256_for_buffer(buffer),
            MatchMethod::Sha1 => calc_sha1_for_buffer(buffer),
            MatchMethod::Md5 => calc_md5_for_buffer(buffer),
        }
    }
}

pub fn check_file<'a>(
    options: &ProcessingOptions,
    df_xml: &'a Document,
    file_path: &Utf8Path,
    hash: &str,
    allow_move: bool,
) -> Result<Vec<Node<'a, 'a>>> {
    let file_name = expect_file_name(file_path)?;
    debug!("hash for '{file_path}' ('{file_name}') = {hash}");
    let mut found_nodes = find_rom_nodes_by_hash(df_xml, options.matches.method.as_str(), hash, options.matches.fast);
    debug!("found nodes by hash {:?}", found_nodes);
    match found_nodes.len() {
        0 => {
            trace!("found no matches, the file appears to be unknown");
            print_file_hash(&options.output, hash, file_path, MatchType::Unknown);
            sort_file(&options.output, file_path, SortOption::Unknown, allow_move);
        }
        1 => {
            trace!("found single match, will use this one");
            let node = found_nodes.first().expect("should never fail as we checked length");
            let node_name = get_name_from_node(node).context("rom nodes in reference dat file should always have a name")?;

            if match_filename(file_name, node_name, options.matches.ignore_suffix) {
                print_file_hash(&options.output, hash, file_path, MatchType::Matched(Option::None));
                sort_file(&options.output, file_path, SortOption::Matched, allow_move);
            } else if allow_move && options.output.rename {
                debug!("renaming {file_path} to {node_name}");
                match rename_file_if_possible(file_path, node_name) {
                    Ok(new_path) => {
                        print_file_hash(&options.output, hash, &new_path, MatchType::Matched(Some(file_path.to_string())));
                        sort_file(&options.output, &new_path, SortOption::Matched, allow_move);
                    }
                    Err(err) => {
                        warn!("could not rename '{file_path}' to '{node_name}' - {err}");
                        print_file_hash(&options.output, hash, file_path, MatchType::Warning(node_name.to_string()));
                        sort_file(&options.output, file_path, SortOption::Warning, allow_move);
                    }
                }
            } else {
                print_file_hash(&options.output, hash, file_path, MatchType::Warning(node_name.to_string()));
                sort_file(&options.output, file_path, SortOption::Warning, allow_move);
            }
        }
        _ => {
            trace!("found multiple matches for hash, trying to match by name");
            if found_nodes
                .iter()
                .any(|node| match_rom_filename(node, file_name, options.matches.ignore_suffix))
            {
                trace!("found at least one match for name, the file is ok, remove other nodes");
                found_nodes.retain(|node| match_rom_filename(node, file_name, options.matches.ignore_suffix));
                print_file_hash(&options.output, hash, file_path, MatchType::Matched(Option::None));
                sort_file(&options.output, file_path, SortOption::Matched, allow_move);
            } else {
                trace!("found no matches for name, the file is misnamed but could be multiple options");
                if options.output.warning.output_files() {
                    println!("[WARN] {hash} {file_path}  - multiple matches, could be one of:");
                    found_nodes
                        .iter()
                        .flat_map(get_name_from_node)
                        .for_each(|name| println!("       {hash} {name}"));
                }

                sort_file(&options.output, file_path, SortOption::Warning, allow_move);
            }
        }
    }
    Ok(found_nodes)
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
pub enum SortOption {
    None,
    Unknown,
    Matched,
    Warning, //misnamed or something incomplete
    All,
}

pub fn sort_file(output: &OutputOptions, file_path: &Utf8Path, sort: SortOption, allow_sort: bool) {
    if allow_sort && (output.sort == sort || output.sort == SortOption::All) {
        let subdir = match sort {
            SortOption::Unknown => "unknown",
            SortOption::Matched => "matched",
            SortOption::Warning => "warning",
            _ => return, // Do nothing
        };
        let new_path = output.sort_dir.join(subdir);
        match move_file_if_possible(file_path, &new_path) {
            Ok(new_name) => info!("moved {file_path} to {new_path} ({new_name})"),
            Err(err) => warn!("could not move '{file_path}' to '{new_path}' - {err}"),
        }
    }
}

enum MatchType {
    Matched(Option<String>),
    Warning(String),
    Unknown,
}

fn print_file_hash(output: &OutputOptions, hash: &str, file_path: &Utf8Path, match_type: MatchType) {
    match match_type {
        MatchType::Matched(old_name) => {
            if let Some(old_name) = old_name {
                println_if!(output.found.output_files(), "[ OK ] {hash} {file_path} (renamed from {old_name})");
            } else {
                println_if!(output.found.output_files(), "[ OK ] {hash} {file_path} ");
            }
        }
        MatchType::Warning(actual_name) => {
            println_if!(output.warning.output_files(), "[WARN] {hash} {file_path}  - misnamed, should be '{actual_name}'");
        }
        MatchType::Unknown => {
            println_if!(output.missing.output_files(), "[MISS] {hash} {file_path} - unknown, no match");
        }
    }
}

fn match_rom_filename(node: &Node, file_name: &str, ignore_suffix: bool) -> bool {
    get_name_from_node(node)
        .map(|rom_name| match_filename(file_name, rom_name, ignore_suffix))
        .unwrap_or_default()
}
