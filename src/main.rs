mod entensions;
mod file_ops;

use crate::entensions::IfSome;
use crate::file_ops::{calc_md5_for_file, calc_sha1_for_file, calc_sha256_for_file, rename_file_if_possible};
use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand, ValueEnum, ValueHint};
use log::{debug, info, trace, warn};
use roxmltree::{Document, Node};
use std::collections::{BTreeMap, BTreeSet};

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
    /// method to use for matching reference entries (note: Sha256 is not well supported)
    #[clap(short, long, value_enum, default_value_t = MatchMethod::Sha1)]
    method: MatchMethod,

    /// fast match mode for single rom games, may show incorrect names if multiple identical hashes
    #[clap(short, long)]
    fast: bool,

    /// rename mismatched files to reference filename if unambiguous
    #[clap(short, long)]
    rename: bool,

    /// list of files to check against reference dat file
    #[clap(required = true, value_parser, value_hint = ValueHint::FilePath)]
    files: Vec<Utf8PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
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

    //debug!("raw xml: {:?}", df_xml);
    match args.command {
        Commands::Check(check_args) => {
            //use a b-tree map for natural sorting
            let mut found_games = BTreeMap::new();

            println!("--FILES--");
            for file_path in &check_args.files {
                if !file_path.is_file() {
                    warn!("{file_path} is not a regular file, skipping it");
                    continue;
                }
                hash_candidate_file(check_args.method, file_path)
                    .with_context(|| format!("could not hash '{file_path}', file will be skipped"))
                    .and_then(|hash_string| check_file(&df_xml, &check_args, file_path, &hash_string))
                    .with_context(|| format!("could not to check '{file_path}', file will be skipped"))
                    .map(|found_rom_nodes| {
                        found_rom_nodes.iter().for_each(|rom_node| {
                            rom_node.parent().filter(is_game_node).if_some(|game_node| {
                                //use a b-tree set for natural sorting
                                let found_roms = found_games.entry(game_node).or_insert_with(BTreeSet::new);
                                found_roms.insert(*rom_node);
                            });
                        });
                    })
                    .err()
                    .if_some(|error| warn!("could not process '{file_path}', error was '{error}'"));
            }

            //process sets
            if !found_games.is_empty() {
                println!("--SETS --");
                for (game, found_roms) in found_games {
                    check_game(&check_args, &game, &found_roms)
                        .err()
                        .if_some(|error| warn!("could not process game, error was '{error}'"));
                }
            }
        }
    }
    Ok(())
}

fn check_file<'a>(df_xml: &'a Document, check_args: &CheckArgs, file_path: &Utf8Path, hash: &str) -> Result<Vec<Node<'a, 'a>>> {
    let file_name = file_path.file_name().context("file path should always have a file name")?;
    debug!("hash for '{file_name}' = {hash}");
    let mut found_nodes = find_rom_nodes_by_hash_attribute(df_xml, check_args.method, hash, !check_args.fast);
    debug!("found nodes by hash {:?}", found_nodes);
    if found_nodes.is_empty() {
        trace!("found no matches, the file appears to be unknown");
        println!("[MISS] {hash} {file_name} - unknown, no match");
    } else if found_nodes.len() == 1 {
        let node = found_nodes.first().expect("should never fail as we checked length");
        trace!("found single match, will use this one");
        let node_name = node
            .attribute("name")
            .context("rom nodes in reference dat file should always have a name")?;

        if node_name == file_name {
            println!("[ OK ] {hash} {file_name}");
        } else {
            println!("[WARN] {hash} {file_name}  - misnamed, should be '{node_name}'");
        }

        if check_args.rename && file_name != node_name {
            debug!("renaming {file_name} to {node_name}");
            rename_file_if_possible(file_path, node_name);
        }
    } else {
        trace!("found multiple matches for hash, trying to match by name");
        if found_nodes.iter().any(|node| node.attribute("name") == Some(file_name)) {
            trace!("found at least one match for name, the file is ok, remove other nodes");
            found_nodes.retain(|node| node.attribute("name") == Some(file_name));
            println!("[ OK ] {hash} {file_name}");
        } else {
            trace!("found at least no matches for name, the file is misnamed but could be multiple options");
            println!("[WARN] {hash} {file_name}  - multiple matches, could be one of:");
            found_nodes
                .iter()
                .map(|node| node.attribute("name"))
                .for_each(|name| println!("       {hash} {}", name.unwrap_or("???")));
        }
    }
    Ok(found_nodes)
}

fn check_game(check_args: &CheckArgs, game: &Node, found_roms: &BTreeSet<Node>) -> Result<()> {
    let all_roms = BTreeSet::from_iter(game.children().filter(is_rom_node));
    let game_name = game
        .attribute("name")
        .context("game nodes in reference dat file should always have a name")?;
    if found_roms.len() == all_roms.len() {
        println!("[ OK ]  {game_name}");
        Ok(())
    } else {
        all_roms.difference(found_roms).try_for_each(|missing| {
            let missing_name = missing
                .attribute("name")
                .context("rom nodes in reference dat file should always have a name")?;
            let missing_hash =
                get_hash_from_rom_node(missing, check_args.method).context("rom nodes in reference dat file should have a hash")?;
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

fn hash_candidate_file(method: MatchMethod, file: &Utf8Path) -> Result<String> {
    match method {
        MatchMethod::Sha256 => calc_sha256_for_file(file),
        MatchMethod::Sha1 => calc_sha1_for_file(file),
        MatchMethod::Md5 => calc_md5_for_file(file),
    }
}

fn hash_attribute_name_for_method(method: MatchMethod) -> &'static str {
    match method {
        MatchMethod::Sha256 => "sha256",
        MatchMethod::Sha1 => "sha1",
        MatchMethod::Md5 => "md5",
    }
}

fn is_game_node(n: &Node) -> bool {
    n.tag_name().name() == "game"
}

fn is_rom_node(n: &Node) -> bool {
    n.tag_name().name() == "rom"
}

fn get_hash_from_rom_node(node: &Node, method: MatchMethod) -> Option<String> {
    node.attribute(hash_attribute_name_for_method(method))
        .map(str::to_ascii_lowercase)
}

fn find_rom_nodes_by_hash_attribute<'a>(
    df_xml: &'a Document,
    method: MatchMethod,
    hash_string: &str,
    multiple: bool,
) -> Vec<Node<'a, 'a>> {
    debug!(
        "looking up '{hash_string}' using method '{}'",
        hash_attribute_name_for_method(method)
    );
    if multiple {
        df_xml
            .descendants()
            .filter(is_rom_node)
            .filter(|n| get_hash_from_rom_node(n, method) == Some(hash_string.to_ascii_lowercase()))
            .collect()
    } else {
        let mut vec = Vec::new();
        df_xml
            .descendants()
            .filter(is_rom_node)
            .find(|n| get_hash_from_rom_node(n, method) == Some(hash_string.to_ascii_lowercase()))
            .iter()
            .for_each(|a| vec.push(*a)); //slightly convoluted because iter() returns a ref instead
        vec
    }
}
