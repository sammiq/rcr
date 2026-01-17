mod dat_ops;
mod file_ops;

use crate::dat_ops::*;
use crate::file_ops::*;

use anyhow::{ensure, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, ValueEnum, ValueHint};
use log::{debug, info, trace, warn};
use rayon::prelude::*;
use roxmltree::ParsingOptions;
use roxmltree::{Document, Node};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

type NodeSet<'x> = BTreeSet<Node<'x, 'x>>;
type GameMap<'x> = BTreeMap<Node<'x, 'x>, NodeSet<'x>>;

#[derive(Debug, Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
     /// count any matches in a zip file as a match, otherwise
    /// the file count must match for a partial match
    #[clap(short, long, verbatim_doc_comment, env = "RCR_ANY_CONTENTS")]
    any_contents: bool,

    /// name of the dat file to use as reference
    #[clap(short, long, value_parser, value_hint = ValueHint::FilePath, env = "RCR_DATFILE")]
    dat_file: Utf8PathBuf,

    /// comma seperated list of suffixes to exclude when scanning,
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

    /// fast match mode for single rom games,
    /// may show incorrect names if multiple identical hashes
    #[clap(short('F'), long, verbatim_doc_comment, env = "RCR_FAST")]
    fast: bool,

    /// which found and matching items to print after scan
    #[clap(short, long, value_enum, default_value_t = OutputFilter::All, env = "RCR_FOUND")]
    found: OutputFilter,

    /// ignore the suffix when checking for name match
    #[clap(short, long, env = "RCR_IGNORE_SUFFIX")]
    ignore_suffix: bool,

    /// default method to use for matching reference entries
    #[clap(short('M'), long, value_enum, default_value_t = MatchMethod::Sha1, verbatim_doc_comment, env = "RCR_METHOD")]
    method: MatchMethod,

    /// which missing items to print after scan
    #[clap(short, long, value_enum, default_value_t = OutputFilter::All, env = "RCR_MISSING")]
    missing: OutputFilter,

    /// rename mismatched files to reference filename if unambiguous
    #[clap(short, long, env = "RCR_RENAME")]
    rename: bool,

    /// recurse into directories specified on command line
    #[clap(short('R'), long, env = "RCR_RECURSE")]
    recurse: bool,

    /// sort files into directories based on match status
    #[clap(short, long, value_enum, default_value_t = SortOption::None, env = "RCR_SORT")]
    sort: SortOption,

    /// base directory to use when sorting files
    #[clap(short('S'), long, value_enum, default_value = ".", env = "RCR_SORT")]
    sort_dir: Utf8PathBuf,

    /// verbose mode, add more of these for more information
    #[clap(short, long, action = clap::ArgAction::Count, env = "RCR_VERBOSE")]
    verbose: u8,

    /// which warning items to print after scan
    #[clap(short, long, value_enum, default_value_t = OutputFilter::All, env = "RCR_MISSING")]
    warning: OutputFilter,

    /// number of threads to use for processing,
    /// may decrease performance if I/O bound
    #[clap(short('W'), long, default_value_t = 1, verbatim_doc_comment, env = "RCR_WORKERS")]
    workers: u8,

    /// list of files to check against reference dat file
    #[clap(required = true, value_parser, value_hint = ValueHint::FilePath)]
    files: Vec<Utf8PathBuf>,
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
enum OutputFilter {
    Files,
    Sets,
    All,
    None,
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
enum SortOption {
    None,
    Unknown,
    Matched,
    Warning, //misnamed or something incomplete
    All,
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
enum MatchMethod {
    Sha256,
    Sha1,
    Md5,
}

impl MatchMethod {
    fn as_str(&self) -> &'static str {
        match self {
            MatchMethod::Sha256 => "sha256",
            MatchMethod::Sha1 => "sha1",
            MatchMethod::Md5 => "md5",
        }
    }

    fn hash_data<R: std::io::Read + ?Sized>(&self, reader: &mut R) -> Result<String> {
        match self {
            MatchMethod::Sha256 => calc_sha256_for_reader(reader),
            MatchMethod::Sha1 => calc_sha1_for_reader(reader),
            MatchMethod::Md5 => calc_md5_for_reader(reader),
        }
    }
}

const EMPTY_TREE: GameMap = GameMap::new();

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .init()
        .expect("should be able to initialize the logger");

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
    if args.sort != SortOption::None {
        const ALL_SUBDIRS: [&str; 3] = ["unknown", "matched", "warning"];
        let subdirs = match args.sort {
            SortOption::None => unreachable!(),
            SortOption::Unknown => &ALL_SUBDIRS[0..1],
            SortOption::Matched => &ALL_SUBDIRS[1..2],
            SortOption::Warning => &ALL_SUBDIRS[2..3],
            SortOption::All => &ALL_SUBDIRS[..],
        };
        for dir_name in subdirs {
            let dir = args.sort_dir.join(dir_name);
            if let Err(e) = std::fs::create_dir_all(&dir) {
                warn!("could not create sort subdirectory '{}', sorting will be disabled. Err: {}", dir, e);
                args.sort = SortOption::None;
                break;
            }
        }
    }

    rayon::ThreadPoolBuilder::new()
        .num_threads(args.workers as usize)
        .build_global()
        .expect("should be able to initialize the thread pool");
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
    let method = sanity_check_match_method(&df_xml, args.method)?;
    if method != args.method {
        args.method = method;
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
            if let Err(error) = check_game(&args, game, found_roms) {
                warn!("could not process game, error was '{error}'");
            }
        }
    }

    let games = df_xml.root_element().children().filter(is_game_node);
    let mut total_games = 0usize;
    if args.missing == OutputFilter::Sets || args.missing == OutputFilter::All {
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

fn merge_game_maps<'x>(
    mut acc: GameMap<'x>,
    e: GameMap<'x>,
) -> GameMap<'x> {
    for (k, v) in e {
        acc.entry(k).or_default().extend(v.iter());
    }
    acc
}

fn process_files<'x>(args: &Cli, df_xml: &'x Document) -> GameMap<'x> {
    let mut exclusions = BTreeSet::new();
    exclusions.extend(args.exclude.iter().cloned());

    println!("--    FILES    --");
    let found_games = args
        .files
        .par_iter()
        .map(|file_path| process_file(args, df_xml, &exclusions, file_path))
        .reduce(GameMap::new, merge_game_maps);

    found_games
}

fn process_file<'x>(args: &Cli, df_xml: &'x Document, exclusions: &BTreeSet<String>, file_path: &Utf8Path) -> GameMap<'x> {
    if is_hidden_file(file_path) {
        info!("{file_path} is hidden, skipping it");
        EMPTY_TREE
    } else if file_path.is_dir() {
        if args.recurse {
            match file_path
                .read_dir_utf8()
                .expect("could not read directory")
                .map(|res| res.map(|e| e.path().to_owned()))
                .collect::<Result<Vec<_>, std::io::Error>>()
            {
                Ok(entries) => entries
                    .par_iter()
                    .map(|path| process_file(args, df_xml, exclusions, path))
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
    } else if file_path.extension().map(|ext| exclusions.contains(ext)).unwrap_or(false) {
        info!("{file_path} has an excluded extension, skipping it");
        EMPTY_TREE
    } else if file_path.extension() == Some("zip") {
        process_zip_file(args, df_xml, file_path)
    } else {
        process_rom_file(args, df_xml, file_path)
    }
}

fn process_rom_file<'x>(args: &Cli, df_xml: &'x Document, file_path: &Utf8Path) -> GameMap<'x> {
    //use a b-tree map for natural sorting
    let mut found_games = GameMap::new();

    match reader_for_filename(file_path)
        .and_then(|mut reader| args.method.hash_data(&mut reader))
        .and_then(|hash_string| check_file(args, df_xml, file_path, &hash_string, true))
    {
        Ok(found_rom_nodes) => {
            for rom_node in found_rom_nodes {
                if let Some(game_node) = rom_node.parent().filter(is_game_node) {
                    //use a b-tree set for natural sorting
                    found_games.entry(game_node).or_insert_with(NodeSet::new).insert(rom_node);
                };
            }
        }
        Err(error) => warn!("could not process '{file_path}', skipping; error was '{error}'"),
    }

    found_games
}

fn process_zip_file<'x>(args: &Cli, df_xml: &'x Document, file_path: &Utf8Path) -> GameMap<'x> {
    //use a b-tree map for natural sorting
    let mut found_games = GameMap::new();

    if let Err(error) = hash_zip_file_contents(file_path, args.method).map(|hashed| {
        let mut unique_games = NodeSet::new();

        for (file, hash_string) in &hashed {
            let mut inner_path = Utf8PathBuf::from(&file_path);
            inner_path.push(file);
            match check_file(args, df_xml, &inner_path, hash_string, false) {
                Ok(found_rom_nodes) => {
                    for rom_node in found_rom_nodes {
                        if let Some(game_node) = rom_node.parent().filter(is_game_node) {
                            unique_games.insert(game_node);
                            //use a b-tree set for natural sorting
                            found_games.entry(game_node).or_insert_with(NodeSet::new).insert(rom_node);
                        };
                    }
                }
                Err(error) => warn!("could not process '{inner_path}', skipping; error was '{error}'"),
            }
        }

        let exact_matches = filter_zip_matches(args, df_xml, file_path, hashed.len(), &mut found_games, &mut unique_games);
        report_zip_file(args, file_path, &unique_games, exact_matches)
    }) {
        warn!("could not process '{file_path}', error was '{error}'")
    }

    found_games
}

fn filter_zip_matches<'x>(
    args: &Cli,
    df_xml: &'x Document<'_>,
    file_path: &Utf8Path,
    num_files: usize,
    found_games: &mut GameMap<'x>,
    unique_games: &mut NodeSet<'x>,
) -> bool {
    let full_games: NodeSet = unique_games
        .extract_if(.., |game_node| {
            let rom_count = game_node.children().filter(is_rom_node).count();
            rom_count == found_games[game_node].len()
        })
        .collect();
    let exact_matches = !full_games.is_empty();
    if exact_matches {
        //only keep the exact matches, the others are irrelevant
        *unique_games = full_games;
        found_games.retain(|game_node, _| unique_games.contains(game_node));
    } else {
        //check whether the zip file is named after a game, and treat it like that game if so.
        let zip_name = file_path.file_name().expect("zip path should contain the file name");
        if let Some(game_node) = df_xml
            .root_element()
            .children()
            .find(|node| is_game_node(node) && get_name_from_node(node) == Some(zip_name))
        {
            //we should treat this as the desired game and not rely on the hash information
            if unique_games
                .iter()
                .any(|game_node| get_name_from_node(game_node) == Some(zip_name))
            {
                //contains the game already, so remove the others
                unique_games.retain(|game_node| get_name_from_node(game_node) == Some(zip_name));
                found_games.retain(|game_node, _| unique_games.contains(game_node));
            } else {
                //doesn't contain the game to add a blank entry for it
                unique_games.clear();
                unique_games.insert(game_node);
                found_games.clear();
                found_games.insert(game_node, NodeSet::new());
            }
        }
    }

    if !args.any_contents {
        //ignore partial matches if the count of files inside the zip is too small
        let full_games: NodeSet = unique_games
            .extract_if(.., |game_node| {
                let rom_count = game_node.children().filter(is_rom_node).count();
                rom_count <= num_files
            })
            .collect();
        if !full_games.is_empty() {
            *unique_games = full_games;
            found_games.retain(|game_node, _| unique_games.contains(game_node));
        }

        //finally if we have lots of matches with 1 file and there are more than a couple of files in the rom, discard them
        let partials = found_games
            .iter()
            .filter(|(game_node, rom_nodes)| {
                let rom_count = game_node.children().filter(is_rom_node).count();
                rom_count > 2 && rom_nodes.len() == 1
            })
            .count();
        if partials == found_games.len() {
            unique_games.clear();
            found_games.clear();
        }
    }
    exact_matches
}

fn report_zip_file(args: &Cli, file_path: &Utf8Path, unique_games: &NodeSet, exact_matches: bool) -> Result<()> {
    match unique_games.len() {
        0 => {
            info!("zip file '{file_path}' seems to match no games");
            if args.missing == OutputFilter::Files || args.missing == OutputFilter::All {
                println!("[MISS] ---------------------------------------- {file_path} - unknown, no match");
            }
            sort_file(args, file_path, SortOption::Unknown, true);
        }
        1 => {
            let game_node = unique_games.iter().next().expect("should never fail as we checked length");
            let game_name = get_name_from_node(game_node).context("game nodes in reference dat file should always have a name")?;
            info!("zip file '{file_path}' matches {game_name}");

            let current_file_path = if args.rename {
                rename_to_game(file_path, game_name)?
            } else {
                file_path.to_path_buf()
            };

            sort_file(
                args,
                &current_file_path,
                if exact_matches {
                    SortOption::Matched
                } else {
                    SortOption::Warning
                },
                true,
            );
        }
        _ => {
            info!("zip file '{file_path}' seems to match multiple games, could be one of:");
            unique_games
                .iter()
                .flat_map(get_name_from_node)
                .for_each(|name| info!("       {name}"));

            sort_file(args, file_path, SortOption::Warning, true);
        }
    }
    Ok(())
}

fn rename_to_game(file_path: &Utf8Path, game_name: &str) -> Result<Utf8PathBuf> {
    let file_name = file_path.file_name().context("file path should always have a file name")?;
    let new_file_name = match file_path.extension() {
        Some(ext) => game_name.to_string() + "." + ext,
        None => game_name.to_string(),
    };
    if file_name != new_file_name {
        debug!("renaming {file_path} to {new_file_name}");
        let result = rename_file_if_possible(file_path, &new_file_name);
        match &result {
            Ok(new_path) => info!("{new_path} (renamed from {file_path}"),
            Err(err) => warn!("could not rename '{file_path}' to '{new_file_name}' - {err}"),
        }
        result
    } else {
        Ok(file_path.to_path_buf())
    }
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
            match method.hash_data(&mut inner_file) {
                Ok(hash) => {
                    debug!("hash for {} in zip {} is {}", inner_file.name(), file, hash);
                    found_files.insert(inner_file.name().to_string(), hash);
                }
                Err(error) => {
                    warn!("could not process '{}' in zip file '{file}', error was '{error}'", inner_file.name())
                }
            }
        }
    }
    Ok(found_files)
}

fn match_rom_filename(node: &Node, file_name: &str, ignore_suffix: bool) -> bool {
    get_name_from_node(node)
        .map(|rom_name| match_filename(file_name, rom_name, ignore_suffix))
        .unwrap_or(false)
}

fn sort_file(args: &Cli, file_path: &Utf8Path, sort: SortOption, allow_sort: bool) {
    if allow_sort && args.sort == sort || args.sort == SortOption::All {
        let subdir = match sort {
            SortOption::Unknown => "unknown",
            SortOption::Matched => "matched",
            SortOption::Warning => "warning",
            _ => return, // Do nothing
        };
        let new_path = args.sort_dir.join(subdir);
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

fn print_file_hash(args: &Cli, hash: &str, file_path: &Utf8Path, match_type: MatchType) {
    match match_type {
        MatchType::Matched(old_name) => {
            if args.found == OutputFilter::Files || args.found == OutputFilter::All {
                if let Some(old_name) = old_name {
                    println!("[ OK ] {hash} {file_path} (renamed from {old_name}");
                } else {
                    println!("[ OK ] {hash} {file_path} ");
                }
            }
        }
        MatchType::Warning(actual_name) => {
            if args.warning == OutputFilter::Files || args.warning == OutputFilter::All {
                println!("[WARN] {hash} {file_path}  - misnamed, should be '{actual_name}'");
            }
        }
        MatchType::Unknown => {
            if args.missing == OutputFilter::Files || args.missing == OutputFilter::All {
                println!("[MISS] {hash} {file_path} - unknown, no match");
            }
        }
    }
}

fn check_file<'a>(
    args: &Cli,
    df_xml: &'a Document,
    file_path: &Utf8Path,
    hash: &str,
    allow_move: bool,
) -> Result<Vec<Node<'a, 'a>>> {
    let file_name = file_path.file_name().context("file path should always have a file name")?;
    debug!("hash for '{file_path}' ('{file_name}') = {hash}");
    let mut found_nodes = find_rom_nodes_by_hash(df_xml, args.method.as_str(), hash, args.fast);
    debug!("found nodes by hash {:?}", found_nodes);
    match found_nodes.len() {
        0 => {
            trace!("found no matches, the file appears to be unknown");
            print_file_hash(args, hash, file_path, MatchType::Unknown);
            sort_file(args, file_path, SortOption::Unknown, allow_move);
        }
        1 => {
            trace!("found single match, will use this one");
            let node = found_nodes.first().expect("should never fail as we checked length");
            let node_name = get_name_from_node(node).context("rom nodes in reference dat file should always have a name")?;

            if match_filename(file_name, node_name, args.ignore_suffix) {
                print_file_hash(args, hash, file_path, MatchType::Matched(Option::None));
                sort_file(args, file_path, SortOption::Matched, allow_move);
            } else if allow_move && args.rename {
                debug!("renaming {file_path} to {node_name}");
                match rename_file_if_possible(file_path, node_name) {
                    Ok(new_path) => {
                        print_file_hash(args, hash, &new_path, MatchType::Matched(Some(file_path.to_string())));
                        sort_file(args, file_path, SortOption::Matched, allow_move);
                    }
                    Err(err) => {
                        warn!("could not rename '{file_path}' to '{node_name}' - {err}");
                        print_file_hash(args, hash, file_path, MatchType::Warning(node_name.into()));
                        sort_file(args, &file_path, SortOption::Warning, allow_move);
                    }
                }
            } else {
                print_file_hash(args, hash, file_path, MatchType::Warning(node_name.into()));
                sort_file(args, &file_path, SortOption::Warning, allow_move);
            }
        }
        _ => {
            trace!("found multiple matches for hash, trying to match by name");
            if found_nodes
                .iter()
                .any(|node| match_rom_filename(node, file_name, args.ignore_suffix))
            {
                trace!("found at least one match for name, the file is ok, remove other nodes");
                found_nodes.retain(|node| match_rom_filename(node, file_name, args.ignore_suffix));
                print_file_hash(args, hash, file_path, MatchType::Matched(Option::None));
                sort_file(args, file_path, SortOption::Matched, allow_move);
            } else {
                trace!("found no matches for name, the file is misnamed but could be multiple options");
                if args.warning == OutputFilter::Files || args.warning == OutputFilter::All {
                    println!("[WARN] {hash} {file_path}  - multiple matches, could be one of:");
                    found_nodes
                        .iter()
                        .flat_map(get_name_from_node)
                        .for_each(|name| println!("       {hash} {name}"));
                }

                sort_file(args, &file_path, SortOption::Warning, allow_move);
            }
        }
    }
    Ok(found_nodes)
}

fn check_game(args: &Cli, game: &Node, found_roms: &NodeSet) -> Result<()> {
    let all_roms: NodeSet = game.children().filter(is_rom_node).collect();
    let game_name = get_name_from_node(game).context("game nodes in reference dat file should always have a name")?;
    if found_roms.len() == all_roms.len() {
        println!("[ OK ]  {game_name}");
        Ok(())
    } else {
        println!("[PART]  {game_name}");
        if args.missing == OutputFilter::Files || args.missing == OutputFilter::All {
            all_roms.difference(found_roms).try_for_each(|missing| {
                let missing_name =
                    get_name_from_node(missing).context("rom nodes in reference dat file should always have a name")?;
                let missing_hash = get_hash_from_rom_node(missing, args.method.as_str())
                    .context("rom nodes in reference dat file should have a hash")?;
                println!("  [MISS]  {missing_hash} {missing_name}");
                Ok(())
            })
        } else {
            Ok(())
        }
    }
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
