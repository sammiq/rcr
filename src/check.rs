use crate::dat_ops::*;
use crate::extensions::*;
use crate::file_ops::*;
use crate::hash::*;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, ValueHint};
use log::{debug, info, trace, warn};
use rayon::prelude::*;
use roxmltree::{Document, Node};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Args)]
pub struct CheckArgs {
    /// fast match mode for single rom games, find only the first match
    /// may show incorrect names if multiple identical hashes
    #[clap(short, long, verbatim_doc_comment, env = "RCR_FAST")]
    fast: bool,

    /// name of the dat file to use as reference
    #[clap(short, long, value_parser, value_hint = ValueHint::FilePath, env = "RCR_DATFILE")]
    dat_file: Utf8PathBuf,

    /// comma seperated list of suffixes to exclude when scanning
    #[clap(short, long, value_delimiter = ',', verbatim_doc_comment, env = "RCR_EXCLUDE")]
    exclude: Vec<String>,

    /// method to use for matching dat-file entries
    /// (note: Sha256 is not well supported in dat files from many sources)
    #[clap(short, long, value_enum, default_value_t = MatchMethod::Sha1, verbatim_doc_comment, env = "RCR_METHOD")]
    method: MatchMethod,

    /// rename mismatched files to reference filename if unambiguous
    #[clap(short, long, env = "RCR_RENAME")]
    rename: bool,

    /// list of files to check against reference dat file
    #[clap(required = true, value_parser, value_hint = ValueHint::FilePath)]
    files: Vec<Utf8PathBuf>,
}

const EMPTY_TREE: BTreeMap<Node, BTreeSet<Node>> = BTreeMap::new();

pub fn run_check(check_args: &CheckArgs) -> Result<()> {
    trace!("reading dat file {}", check_args.dat_file);
    //read in the xml to buffer, roxmltree will reference into this buffer for the document and all nodes
    let df_buffer = std::fs::read_to_string(&check_args.dat_file).context("Unable to read reference dat file")?;
    let df_xml = Document::parse(df_buffer.as_str()).context("Unable to parse reference dat file")?;
    info!("dat file {} read successfully", check_args.dat_file);

    //ensure that the dat file will support this usage
    let method = sanity_check_match_method(&df_xml, check_args.method)?;
    if method != check_args.method {
        warn!(
            "matching files using {} after checking, as reference dat file is missing {}",
            method, &check_args.method
        );
    }

    let found_games = check_files(check_args, &df_xml, method);

    //process sets
    if !found_games.is_empty() {
        println!("--SETS --");
        for (game, found_roms) in found_games {
            check_game(method, &game, &found_roms).if_err(|error| warn!("could not process game, error was '{error}'"));
        }
    }

    Ok(())
}

fn check_files<'x>(
    check_args: &CheckArgs,
    df_xml: &'x Document,
    method: MatchMethod,
) -> BTreeMap<Node<'x, 'x>, BTreeSet<Node<'x, 'x>>> {
    let mut exclusions = BTreeSet::new();
    exclusions.extend(check_args.exclude.iter().cloned());

    println!("--FILES--");
    let found_games = check_args
        .files
        .par_iter()
        .map(|file_path| {
            if !file_path.is_file() {
                warn!("{file_path} is not a regular file, skipping it");
                EMPTY_TREE
            } else if file_path.extension().map(|ext| exclusions.contains(ext)).unwrap_or(false) {
                info!("{file_path} is has an excluded extension, skipping it");
                EMPTY_TREE
            } else if file_path.extension() == Some("zip") {
                check_zip_file(check_args, df_xml, file_path, method)
            } else {
                check_rom_file(check_args, df_xml, file_path, method)
            }
        })
        .reduce(BTreeMap::new, |mut acc, e| {
            for (k, v) in e {
                acc.entry(k).or_insert_with(BTreeSet::new).extend(v.iter());
            }
            acc
        });

    found_games
}

fn check_rom_file<'x>(
    check_args: &CheckArgs,
    df_xml: &'x Document,
    file_path: &Utf8PathBuf,
    method: MatchMethod,
) -> BTreeMap<Node<'x, 'x>, BTreeSet<Node<'x, 'x>>> {
    //use a b-tree map for natural sorting
    let mut found_games = BTreeMap::new();

    reader_for_filename(file_path)
        .and_then(|mut reader| hash_file_with_method(&mut reader, method))
        .and_then(|hash_string| check_file(df_xml, file_path, &hash_string, method, check_args.fast, check_args.rename))
        .map(|found_rom_nodes| {
            for rom_node in found_rom_nodes {
                rom_node.parent().filter(is_game_node).if_some(|game_node| {
                    //use a b-tree set for natural sorting
                    found_games.entry(game_node).or_insert_with(BTreeSet::new).insert(rom_node);
                });
            }
        })
        .if_err(|error| warn!("could not process '{file_path}', skipping; error was '{error}'"));

    found_games
}

fn check_zip_file<'x>(
    check_args: &CheckArgs,
    df_xml: &'x Document,
    file_path: &Utf8PathBuf,
    method: MatchMethod,
) -> BTreeMap<Node<'x, 'x>, BTreeSet<Node<'x, 'x>>> {
    //use a b-tree map for natural sorting
    let mut found_games = BTreeMap::new();

    hash_zip_file_contents(file_path, method)
        .map(|hashed| {
            let mut unique_games = BTreeSet::new();

            for (file, hash_string) in hashed {
                let mut inner_path = Utf8PathBuf::from(&file);
                inner_path.push(file);
                check_file(df_xml, &inner_path, &hash_string, method, check_args.fast, false)
                    .map(|found_rom_nodes| {
                        for rom_node in found_rom_nodes {
                            rom_node.parent().filter(is_game_node).if_some(|game_node| {
                                unique_games.insert(game_node);
                                //use a b-tree set for natural sorting
                                found_games.entry(game_node).or_insert_with(BTreeSet::new).insert(rom_node);
                            });
                        }
                    })
                    .if_err(|error| warn!("could not process '{inner_path}', skipping; error was '{error}'"));
            }

            report_zip_file(file_path, &unique_games, check_args.rename)
        })
        .if_err(|error| warn!("could not process '{file_path}', error was '{error}'"));

    found_games
}

fn report_zip_file(file_path: &Utf8Path, unique_games: &BTreeSet<Node>, rename: bool) -> Result<()> {
    match unique_games.len() {
        0 => info!("zip file '{file_path}' seems to match no games"),
        1 => {
            let game_node = unique_games.iter().next().expect("should never fail as we checked length");
            let game_name = get_name_from_node(game_node).context("game nodes in reference dat file should always have a name")?;
            info!("zip file '{file_path}' matches {game_name}");
            if rename {
                rename_preserving_extension(file_path, game_name)?;
            }
        }
        _ => {
            warn!("zip file '{file_path}' seems to match multiple games, could be one of:");
            unique_games
                .iter()
                .flat_map(get_name_from_node)
                .for_each(|name| warn!("       {name}"));
        }
    }
    Ok(())
}

fn check_file<'a>(
    df_xml: &'a Document,
    file_path: &Utf8Path,
    hash: &str,
    method: MatchMethod,
    fast: bool,
    rename: bool,
) -> Result<Vec<Node<'a, 'a>>> {
    let file_name = file_path.file_name().context("file path should always have a file name")?;
    debug!("hash for '{file_path}' ('{file_name}') = {hash}");
    let mut found_nodes = find_rom_nodes_by_hash(df_xml, &method.to_string(), hash, fast);
    debug!("found nodes by hash {:?}", found_nodes);
    match found_nodes.len() {
        0 => {
            trace!("found no matches, the file appears to be unknown");
            println!("[MISS] {hash} {file_path} - unknown, no match");
        }
        1 => {
            trace!("found single match, will use this one");
            let node = found_nodes.first().expect("should never fail as we checked length");
            let node_name = get_name_from_node(node).context("rom nodes in reference dat file should always have a name")?;

            if node_name == file_name {
                println!("[ OK ] {hash} {file_path}");
            } else if rename {
                debug!("renaming {file_path} to {node_name}");
                match rename_file_if_possible(file_path, node_name) {
                    Ok(new_path) => println!("[ OK ] {hash} {new_path} (renamed from {file_path}"),
                    Err(err) => {
                        warn!("could not rename '{file_path}' to '{node_name}' - {err}");
                        println!("[WARN] {hash} {file_path}  - misnamed, should be '{node_name}'");
                    }
                }
            } else {
                println!("[WARN] {hash} {file_path}  - misnamed, should be '{node_name}'");
            }
        }
        _ => {
            trace!("found multiple matches for hash, trying to match by name");
            if found_nodes.iter().any(|node| get_name_from_node(node) == Some(file_name)) {
                trace!("found at least one match for name, the file is ok, remove other nodes");
                found_nodes.retain(|node| get_name_from_node(node) == Some(file_name));
                println!("[ OK ] {hash} {file_path}");
            } else {
                trace!("found at least no matches for name, the file is misnamed but could be multiple options");
                println!("[WARN] {hash} {file_path}  - multiple matches, could be one of:");
                found_nodes
                    .iter()
                    .flat_map(get_name_from_node)
                    .for_each(|name| println!("       {hash} {name}"));
            }
        }
    }
    Ok(found_nodes)
}

fn check_game(method: MatchMethod, game: &Node, found_roms: &BTreeSet<Node>) -> Result<()> {
    let all_roms: BTreeSet<Node> = game.children().filter(is_rom_node).collect();
    let game_name = get_name_from_node(game).context("game nodes in reference dat file should always have a name")?;
    if found_roms.len() == all_roms.len() {
        println!("[ OK ]  {game_name}");
        Ok(())
    } else {
        all_roms.difference(found_roms).try_for_each(|missing| {
            let missing_name = get_name_from_node(missing).context("rom nodes in reference dat file should always have a name")?;
            let missing_hash = get_hash_from_rom_node(missing, &method.to_string())
                .context("rom nodes in reference dat file should have a hash")?;
            println!("[WARN]  {game_name} is missing {missing_hash} {missing_name}");
            Ok(())
        })
    }
}
