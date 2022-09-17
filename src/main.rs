mod dat_ops;
mod extensions;
mod file_ops;

use crate::dat_ops::*;
use crate::extensions::*;
use crate::file_ops::*;

use anyhow::{ensure, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, ValueEnum, ValueHint};
use log::{debug, info, trace, warn};
use roxmltree::{Document, Node};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

#[derive(Debug, Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// verbose mode, add more of these for more information
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// method to use for matching reference entries
    /// (note: Sha256 is not well supported in dat files from many sources)
    #[clap(short, long, value_enum, default_value_t = MatchMethod::Sha1, verbatim_doc_comment)]
    method: MatchMethod,

    /// fast match mode for single rom games,
    /// may show incorrect names if multiple identical hashes
    #[clap(short, long, verbatim_doc_comment)]
    fast: bool,

    /// rename mismatched files to reference filename if unambiguous
    #[clap(short, long)]
    rename: bool,

    /// name of the dat file to use as reference
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    dat_file: Utf8PathBuf,

    /// list of files to check against reference dat file
    #[clap(required = true, value_parser, value_hint = ValueHint::FilePath)]
    files: Vec<Utf8PathBuf>,
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
enum MatchMethod {
    Sha256,
    Sha1,
    Md5,
}

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .init()
        .expect("should be able to initialize the logger");

    //wild takes care of globbing on windows instead of manually doing it ourselves
    let args = Cli::parse_from(wild::args_os());
    set_logging_level(args.verbose);
    debug!("raw args: {:?}", args);

    trace!("reading dat file {}", args.dat_file);
    //read in the xml to buffer, roxmltree is a bit fiddly with ownership
    let df_buffer = std::fs::read_to_string(&args.dat_file).context("Unable to read reference dat file")?;
    let df_xml = Document::parse(df_buffer.as_str()).context("Unable to parse reference dat file")?;
    info!("dat file {} read successfully", args.dat_file);

    //ensure that the dat file will support this usage
    let method = sanity_check_match_method(&df_xml, args.method)?;
    if method != args.method {
        warn!(
            "matching files using {} after checking, as reference dat file missing those data",
            hash_name_for_method(method)
        );
    }

    //use a b-tree map for natural sorting
    let mut found_games = BTreeMap::new();

    println!("--FILES--");
    for file_path in &args.files {
        if !file_path.is_file() {
            warn!("{file_path} is not a regular file, skipping it");
            continue;
        }

        if file_path.extension() == Some("zip") {
            hash_zip_file_contents(file_path, method)
                .map(|hashed| {
                    for (file, hash_string) in hashed {
                        let mut inner_path = Utf8PathBuf::from(&file);
                        inner_path.push(file);
                        check_file(&df_xml, &inner_path, &hash_string, method, args.fast, false)
                            .and_then(|found_rom_nodes| {
                                let mut game_nodes = BTreeSet::new();
                                for rom_node in found_rom_nodes {
                                    rom_node.parent().filter(is_game_node).if_some(|game_node| {
                                        game_nodes.insert(game_node);
                                        //use a b-tree set for natural sorting
                                        found_games.entry(game_node).or_insert_with(BTreeSet::new).insert(rom_node);
                                    });
                                }

                                if game_nodes.is_empty() {
                                    info!("zip file '{file_path}' seems to match no games");
                                } else if game_nodes.len() > 1 {
                                    warn!("zip file '{file_path}' seems to match multiple games, could be one of:");
                                    game_nodes
                                        .iter()
                                        .flat_map(get_name_from_node)
                                        .for_each(|name| warn!("       {name}"));
                                } else if args.rename {
                                    let game_node = game_nodes.iter().next().expect("should never fail as we checked length");
                                    rename_to_game(file_path, game_node)?;
                                }
                                Ok(())
                            })
                            .err()
                            .if_some(|error| warn!("could not process '{inner_path}', skipping; error was '{error}'"));
                    }
                })
                .err()
                .if_some(|error| warn!("could not process '{file_path}', error was '{error}'"));
        } else {
            reader_for_filename(file_path)
                .and_then(|mut reader| hash_candidate_file_with_method(&mut reader, method))
                .and_then(|hash_string| check_file(&df_xml, file_path, &hash_string, method, args.fast, args.rename))
                .map(|found_rom_nodes| {
                    for rom_node in found_rom_nodes {
                        rom_node.parent().filter(is_game_node).if_some(|game_node| {
                            //use a b-tree set for natural sorting
                            found_games.entry(game_node).or_insert_with(BTreeSet::new).insert(rom_node);
                        });
                    }
                })
                .err()
                .if_some(|error| warn!("could not process '{file_path}', skipping; error was '{error}'"));
        }
    }

    //process sets
    if !found_games.is_empty() {
        println!("--SETS --");
        for (game, found_roms) in found_games {
            check_game(method, &game, &found_roms)
                .err()
                .if_some(|error| warn!("could not process game, error was '{error}'"));
        }
    }

    Ok(())
}

fn rename_to_game(file_path: &Utf8Path, game_node: &Node) -> Result<()> {
    let game_name = get_name_from_node(game_node).context("game nodes in reference dat file should always have a name")?;
    let file_name = file_path.file_name().context("file path should always have a file name")?;
    let new_file_name = match file_path.extension() {
        Some(ext) => game_name.to_string() + "." + ext,
        None => game_name.to_string(),
    };
    if file_name != new_file_name {
        debug!("renaming {file_path} to {new_file_name}");
        match rename_file_if_possible(file_path, &new_file_name) {
            Ok(new_path) => info!("{new_path} (renamed from {file_path}"),
            Err(err) => warn!("could not rename '{file_path}' to '{new_file_name}' - {err}")
        }
    }
    Ok(())
}

fn sanity_check_match_method(df_xml: &Document, method: MatchMethod) -> Result<MatchMethod> {
    sanity_check_match_method_inner(df_xml, method, 0)
}

fn sanity_check_match_method_inner(df_xml: &Document, method: MatchMethod, recursion: u8) -> Result<MatchMethod> {
    //check whether this file has those methods
    if df_xml
        .descendants()
        .filter(is_rom_node)
        .any(|n| get_hash_from_rom_node(&n, hash_name_for_method(method)).is_some())
    {
        Ok(method)
    } else {
        match method {
            MatchMethod::Sha256 => sanity_check_match_method_inner(df_xml, MatchMethod::Sha1, recursion + 1),
            MatchMethod::Sha1 => sanity_check_match_method_inner(df_xml, MatchMethod::Md5, recursion + 1),
            MatchMethod::Md5 => {
                //if we hit here and recursion > 0 then don't keep going as it means we've already tried Sha1
                ensure!(recursion == 0, "no valid methods found in reference dat file");
                sanity_check_match_method_inner(df_xml, MatchMethod::Sha1, recursion + 1)
            }
        }
    }
}

fn hash_zip_file_contents(file: &Utf8Path, method: MatchMethod) -> Result<BTreeMap<String, String>> {
    let f = File::open(file).with_context(|| format!("could not open file '{file}'"))?;
    let mut zip = zip::ZipArchive::new(f).with_context(|| format!("could not open '{file}' as a zip file"))?;
    let mut found_files = BTreeMap::new();
    for i in 0..zip.len() {
        let mut inner_file = zip.by_index(i)?; //fix error
        if inner_file.is_file() {
            hash_candidate_file_with_method(&mut inner_file, method)
                .map(|hash| {
                    debug!("hash for {} in zip {} is {}", inner_file.name(), file, hash);
                    found_files.insert(inner_file.name().to_string(), hash);
                })
                .err()
                .if_some(|error| warn!("could not process '{}' in zip file '{file}', error was '{error}'", inner_file.name()));
        }
    }
    Ok(found_files)
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
    let mut found_nodes = find_rom_nodes_by_hash(df_xml, hash_name_for_method(method), hash, fast);
    debug!("found nodes by hash {:?}", found_nodes);
    if found_nodes.is_empty() {
        trace!("found no matches, the file appears to be unknown");
        println!("[MISS] {hash} {file_path} - unknown, no match");
    } else if found_nodes.len() == 1 {
        let node = found_nodes.first().expect("should never fail as we checked length");
        trace!("found single match, will use this one");
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
    } else {
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
            let missing_hash = get_hash_from_rom_node(missing, hash_name_for_method(method))
                .context("rom nodes in reference dat file should have a hash")?;
            println!("[WARN]  {game_name} is missing {missing_hash} {missing_name}");
            Ok(())
        })
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

fn hash_candidate_file_with_method<R: std::io::Read + ?Sized>(reader: &mut R, method: MatchMethod) -> Result<String> {
    match method {
        MatchMethod::Sha256 => calc_sha256_for_reader(reader),
        MatchMethod::Sha1 => calc_sha1_for_reader(reader),
        MatchMethod::Md5 => calc_md5_for_reader(reader),
    }
}

fn hash_name_for_method(method: MatchMethod) -> &'static str {
    match method {
        MatchMethod::Sha256 => "sha256",
        MatchMethod::Sha1 => "sha1",
        MatchMethod::Md5 => "md5",
    }
}
