mod common;
mod dat_ops;
mod file_ops;
mod zip_file;

use crate::common::*;
use crate::dat_ops::*;
use crate::file_ops::*;
use crate::zip_file::*;

use anyhow::{ensure, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, ValueHint};
use log::{debug, info, trace, warn};
use rayon::prelude::*;
use roxmltree::ParsingOptions;
use roxmltree::{Document, Node};

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "memmap2")]
use memmap2::Mmap;
#[cfg(feature = "memmap2")]
use std::fs::File;

type NodeSet<'x> = BTreeSet<Node<'x, 'x>>;
type GameMap<'x> = BTreeMap<Node<'x, 'x>, NodeSet<'x>>;

#[derive(Debug, Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    options: ProcessingOptions,

    /// name of the dat file to use as reference
    #[clap(short, long, value_parser, value_hint = ValueHint::FilePath, env = "RCR_DATFILE")]
    dat_file: Utf8PathBuf,

    /// comma separated list of suffixes to exclude when scanning,
    /// overrides any files on command line
    #[clap(
        short,
        long,
        value_delimiter = ',',
        default_value = "m3u,dat,txt",
        verbatim_doc_comment,
        env = "RCR_EXCLUDE",
        num_args=1..
    )]
    exclude: Vec<String>,

    /// recurse into directories specified on command line
    #[clap(short('R'), long, env = "RCR_RECURSE")]
    recurse: bool,

    /// number of threads to use for processing,
    /// may decrease performance if I/O bound
    #[clap(short('W'), long, default_value_t = 1, verbatim_doc_comment, env = "RCR_WORKERS")]
    workers: u8,

    /// verbose mode, add more of these for more information
    #[clap(short, long, action = clap::ArgAction::Count, env = "RCR_VERBOSE")]
    verbose: u8,

    /// list of files to check against reference dat file
    #[clap(required = true, value_parser, value_hint = ValueHint::FilePath)]
    files: Vec<Utf8PathBuf>,
}

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .init()
        .context("failed to initialize the logger")?;

    //load .env file from current directory only
    if let Ok(mut path) = std::env::current_dir() {
        path.push(".env");
        if path.is_file() {
            dotenvy::from_path(path).context("Unable to read .env file (possibly malformed input)")?;
        }
    }

    //wild takes care of globbing on windows instead of manually doing it ourselves
    let mut args = Cli::parse_from(wild::args_os());
    set_logging_level(args.verbose);
    debug!("raw args: {:?}", args);

    //if sort is not none, then we need to ensure the sort directory exists and is writable
    if args.options.output.sort != SortOption::None {
        const ALL_SUBDIRS: [&str; 3] = ["unknown", "matched", "warning"];
        let subdirs = match args.options.output.sort {
            SortOption::None => unreachable!(),
            SortOption::Unknown => &ALL_SUBDIRS[0..1],
            SortOption::Matched => &ALL_SUBDIRS[1..2],
            SortOption::Warning => &ALL_SUBDIRS[2..3],
            SortOption::All => &ALL_SUBDIRS[..],
        };
        for dir_name in subdirs {
            let dir = args.options.output.sort_dir.join(dir_name);
            if let Err(e) = std::fs::create_dir_all(&dir) {
                warn!("could not create sort subdirectory '{}', sorting will be disabled. Err: {}", dir, e);
                args.options.output.sort = SortOption::None;
                break;
            }
        }
    }

    rayon::ThreadPoolBuilder::new()
        .num_threads(args.workers as usize)
        .build_global()
        .context("failed to initialize the thread pool")?;
    info!("using {} threads for processing", args.workers);

    trace!("reading dat file {}", args.dat_file);
    //read in the xml to buffer, roxmltree is a bit fiddly with ownership
    let df_buffer = std::fs::read_to_string(&args.dat_file).context("Unable to read reference dat file")?;
    let df_xml = Document::parse_with_options(
        df_buffer.as_str(),
        ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .context("Unable to parse reference dat file")?;
    info!("dat file {} read successfully", args.dat_file);

    //ensure that the dat file will support this usage
    let method = sanity_check_match_method(&df_xml, args.options.matches.method)?;
    if method != args.options.matches.method {
        args.options.matches.method = method;
        warn!(
            "matching files using {} after checking, as reference dat file missing requested format",
            method.as_str()
        );
    }

    let found_games = process_files(&args, &df_xml);

    //process sets
    if !found_games.is_empty() {
        println!();
        println!("-- FOUND SETS  --");
        for (game, found_roms) in &found_games {
            if let Err(error) = check_game(&args.options, game, found_roms) {
                warn!("could not process game, error was '{error}'");
            }
        }
    }

    let games = df_xml.root_element().children().filter(is_game_node);
    let mut total_games = 0usize;
    if args.options.output.missing.output_sets() {
        let found_names: BTreeSet<&str> = found_games
            .keys()
            .map(|k| get_name_from_node(k).unwrap_or_default())
            .collect();
        println!();
        println!("--MISSING SETS --");
        for game in games {
            total_games += 1;
            let game_name = get_name_from_node(&game).context("game nodes in reference dat file should always have a name")?;
            if !found_names.contains(game_name) {
                println!("[MISS]  {game_name}");
            }
        }
    } else {
        total_games = games.count();
    }

    println!();
    println!("Found {}/{} sets ({} Missing)", found_games.len(), total_games, total_games - found_games.len());

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

fn sanity_check_match_method(df_xml: &Document, method: MatchMethod) -> Result<MatchMethod> {
    sanity_check_match_method_inner(df_xml, method, 0)
}

fn sanity_check_match_method_inner(df_xml: &Document, method: MatchMethod, recursion: u8) -> Result<MatchMethod> {
    //check whether this file has those methods
    if df_xml
        .descendants()
        .filter(is_rom_node)
        .any(|n| get_hash_from_rom_node(&n, method.as_str()).is_some())
    {
        Ok(method)
    } else {
        ensure!(recursion < 2, "no valid methods found in reference dat file");
        let next = match method {
            MatchMethod::Sha256 => MatchMethod::Sha1,
            MatchMethod::Sha1 => MatchMethod::Md5,
            MatchMethod::Md5 => MatchMethod::Sha256,
        };
        sanity_check_match_method_inner(df_xml, next, recursion + 1)
    }
}

fn merge_game_maps<'x>(mut acc: GameMap<'x>, e: GameMap<'x>) -> GameMap<'x> {
    for (k, v) in e {
        acc.entry(k).or_default().extend(v.iter());
    }
    acc
}

fn process_files<'x>(args: &Cli, df_xml: &'x Document) -> GameMap<'x> {
    println!("--    FILES    --");
    let found_games = args
        .files
        .par_iter()
        .map(|file_path| process_file(args, df_xml, file_path))
        .reduce(GameMap::new, merge_game_maps);

    found_games
}

fn process_file<'x>(args: &Cli, df_xml: &'x Document, file_path: &Utf8Path) -> GameMap<'x> {
    const EMPTY_TREE: GameMap = GameMap::new();

    if is_hidden_file(file_path) {
        info!("{file_path} is hidden, skipping it");
        EMPTY_TREE
    } else if file_path.is_dir() {
        if args.recurse {
            match file_path.read_dir_utf8().and_then(|dir| {
                dir.map(|res| res.map(|e| e.path().to_owned()))
                    .collect::<Result<Vec<_>, std::io::Error>>()
            }) {
                Ok(entries) => entries
                    .par_iter()
                    .map(|path| process_file(args, df_xml, path))
                    .reduce(GameMap::new, merge_game_maps),
                Err(err) => {
                    warn!("directory {file_path} could not be read due to {err}, skipping it");
                    EMPTY_TREE
                }
            }
        } else {
            info!("{file_path} is a directory, skipping it (use -R to recurse)");
            EMPTY_TREE
        }
    } else if !file_path.is_file() {
        warn!("{file_path} is not a regular file, skipping it");
        EMPTY_TREE
    } else if file_path
        .extension()
        .map(|ext| args.exclude.iter().any(|e| e == ext))
        .unwrap_or_default()
    {
        info!("{file_path} has an excluded extension, skipping it");
        EMPTY_TREE
    } else if file_path.extension() == Some("zip") {
        process_zip_file(&args.options, df_xml, file_path)
    } else {
        process_rom_file(&args.options, df_xml, file_path)
    }
}

#[cfg(feature = "memmap2")]
fn process_rom_file<'x>(options: &ProcessingOptions, df_xml: &'x Document, file_path: &Utf8Path) -> GameMap<'x> {
    //use a b-tree map for natural sorting
    let mut found_games = GameMap::new();

    match File::open(file_path).map_err(anyhow::Error::from).and_then(|f| {
        let mmap = unsafe { Mmap::map(&f)? };
        let hash_string = options.matches.method.hash_data_buffer(&mmap)?;
        check_file(options, df_xml, file_path, &hash_string, true)
    }) {
        Ok(found_rom_nodes) => {
            for rom_node in found_rom_nodes {
                if let Some(game_node) = rom_node.parent().filter(is_game_node) {
                    //use a b-tree set for natural sorting
                    found_games.entry(game_node).or_default().insert(rom_node);
                };
            }
        }
        Err(error) => warn!("could not process '{file_path}', skipping; error was '{error}'"),
    }

    found_games
}

#[cfg(not(feature = "memmap2"))]
fn process_rom_file<'x>(options: &ProcessingOptions, df_xml: &'x Document, file_path: &Utf8Path) -> GameMap<'x> {
    //use a b-tree map for natural sorting
    let mut found_games = GameMap::new();

    match reader_for_filename(file_path)
        .and_then(|mut reader| options.matches.method.hash_data(&mut reader))
        .and_then(|hash_string| check_file(options, df_xml, file_path, &hash_string, true))
    {
        Ok(found_rom_nodes) => {
            for rom_node in found_rom_nodes {
                if let Some(game_node) = rom_node.parent().filter(is_game_node) {
                    //use a b-tree set for natural sorting
                    found_games.entry(game_node).or_default().insert(rom_node);
                };
            }
        }
        Err(error) => warn!("could not process '{file_path}', skipping; error was '{error}'"),
    }

    found_games
}

fn check_game(options: &ProcessingOptions, game: &Node, found_roms: &NodeSet) -> Result<()> {
    let all_roms: NodeSet = game.children().filter(is_rom_node).collect();
    let game_name = get_name_from_node(game).context("game nodes in reference dat file should always have a name")?;
    if found_roms.len() == all_roms.len() {
        println_if!(options.output.found.output_sets(), "[ OK ]  {game_name}");
    } else if options.output.warning.output_sets() {
        println!("[WARN]  {game_name} - is missing files");
        if options.output.missing.output_files() {
            all_roms.difference(found_roms).try_for_each::<_, Result<()>>(|missing| {
                let missing_name =
                    get_name_from_node(missing).context("rom nodes in reference dat file should always have a name")?;
                let missing_hash = get_hash_from_rom_node(missing, options.matches.method.as_str())
                    .context("rom nodes in reference dat file should have a hash")?;
                println!("        {game_name} - {missing_hash} {missing_name}");
                Ok(())
            })?;
        }
    }

    Ok(())
}
