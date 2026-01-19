use crate::common::*;
use crate::dat_ops::*;
use crate::file_ops::*;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use log::{debug, info, warn};
use roxmltree::{Document, Node};

use crate::println_if;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

type NodeSet<'x> = BTreeSet<Node<'x, 'x>>;
type GameMap<'x> = BTreeMap<Node<'x, 'x>, NodeSet<'x>>;

pub fn process_zip_file<'x>(options: &ProcessingOptions, df_xml: &'x Document, file_path: &Utf8Path) -> GameMap<'x> {
    //use a b-tree map for natural sorting
    let mut found_games = GameMap::new();

    if let Err(error) = hash_zip_file_contents(file_path, options.matches.method).and_then(|hashed| {
        let mut unique_games = NodeSet::new();

        for (file, hash_string) in &hashed {
            let mut inner_path = Utf8PathBuf::from(&file_path);
            inner_path.push(file);
            match check_file(options, df_xml, &inner_path, hash_string, false) {
                Ok(found_rom_nodes) => {
                    for rom_node in found_rom_nodes {
                        if let Some(game_node) = rom_node.parent().filter(is_game_node) {
                            unique_games.insert(game_node);
                            //use a b-tree set for natural sorting
                            found_games.entry(game_node).or_default().insert(rom_node);
                        };
                    }
                }
                Err(error) => warn!("could not process '{inner_path}', skipping; error was '{error}'"),
            }
        }

        let exact_matches =
            filter_zip_matches(&options.matches, df_xml, file_path, hashed.len(), &mut found_games, &mut unique_games);
        report_zip_file(&options.output, file_path, &unique_games, exact_matches)
    }) {
        warn!("could not process '{file_path}', error was '{error}'");
    }

    found_games
}

fn hash_zip_file_contents(file: &Utf8Path, method: MatchMethod) -> Result<BTreeMap<String, String>> {
    let f = File::open(file).with_context(|| format!("could not open file '{file}'"))?;
    let mut zip = zip::ZipArchive::new(f).with_context(|| format!("could not open '{file}' as a zip file"))?;
    let mut found_files = BTreeMap::new();
    for i in 0..zip.len() {
        match zip.by_index(i) {
            Ok(mut inner_file) => {
                if inner_file.is_file() {
                    match method.hash_data(&mut inner_file) {
                        Ok(hash) => {
                            debug!("hash for {} in zip {} is {}", inner_file.name(), file, hash);
                            found_files.insert(inner_file.name().to_string(), hash);
                        }
                        Err(error) => warn!("could not process '{}' in zip file '{file}', error was '{error}'", inner_file.name()),
                    }
                } else {
                    info!("skipping entry {i} in zip file '{file}' as it is not a file");
                }
            }
            Err(error) => warn!("could not process entry {i} in zip file '{file}', error was '{error}'"),
        }
    }
    Ok(found_files)
}

fn filter_zip_matches<'x>(
    matches: &MatchOptions,
    df_xml: &'x Document<'_>,
    file_path: &Utf8Path,
    num_files: usize,
    found_games: &mut GameMap<'x>,
    unique_games: &mut NodeSet<'x>,
) -> bool {
    let full_games: NodeSet = unique_games
        .iter()
        .filter(|game_node| {
            let rom_count = game_node.children().filter(is_rom_node).count();
            rom_count == found_games[game_node].len()
        })
        .cloned()
        .collect();

    let exact_matches = !full_games.is_empty();
    if exact_matches {
        //if there are matches for all items, then these are the returned matches
        *unique_games = full_games;
        found_games.retain(|game_node, _| unique_games.contains(game_node));
    } else {
            filter_zip_matches_by_name(df_xml, file_path, found_games, unique_games);
            match matches.mode {
                MatchMode::Any => {},
                MatchMode::Partial => filter_zip_matches_by_count(num_files, found_games, unique_games),
                MatchMode::Strict => {
                    //if there are no exact matches, then treat this like no matches
                    unique_games.clear();
                    found_games.clear()
                },
            }
    }

    exact_matches
}

fn filter_zip_matches_by_count(num_files: usize, found_games: &mut GameMap, unique_games: &mut NodeSet) {
    //ignore partial matches if the count of files inside the zip is too small
    let full_games: NodeSet = unique_games
        .iter()
        .filter(|game_node| {
            let rom_count = game_node.children().filter(is_rom_node).count();
            rom_count <= num_files
        })
        .cloned()
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

fn filter_zip_matches_by_name<'x>(
    df_xml: &'x Document<'_>,
    file_path: &Utf8Path,
    found_games: &mut GameMap<'x>,
    unique_games: &mut NodeSet<'x>,
) {
    //check whether the zip file is named after a game, and treat it like that game if so.
    if let Some(game_node) = df_xml
        .root_element()
        .children()
        .find(|node| is_game_node(node) && match_game_name(node, file_path))
    {
        //we should treat this as the desired game and not rely on the hash information
        if unique_games.iter().any(|game_node| match_game_name(game_node, file_path)) {
            //contains the game already, so remove the others
            unique_games.retain(|game_node| match_game_name(game_node, file_path));
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

fn match_game_name(node: &Node, file_path: &Utf8Path) -> bool {
    get_name_from_node(node)
        .and_then(|node_name| file_path.file_stem().map(|zip_name| node_name == zip_name))
        .unwrap_or_default()
}

fn report_zip_file(output: &OutputOptions, file_path: &Utf8Path, unique_games: &NodeSet, exact_matches: bool) -> Result<()> {
    let mut path = file_path.to_owned();
    let sort_option = match unique_games.len() {
        0 => {
            info!("zip file '{file_path}' seems to match no games");
            println_if!(
                output.missing.output_files(),
                "[MISS] ---------------------------------------- {file_path} - unknown, no match"
            );

            SortOption::Unknown
        }
        1 => {
            let game_node = unique_games.first().expect("should never fail as we checked length");
            let game_name = get_name_from_node(game_node).context("game nodes in reference dat file should always have a name")?;
            info!("zip file '{file_path}' matches {game_name}");

            path = if output.rename { rename_to_game(file_path, game_name)? } else { file_path.to_path_buf() };

            if exact_matches {
                SortOption::Matched
            } else {
                SortOption::Warning
            }
        }
        _ => {
            info!("zip file '{file_path}' seems to match multiple games, could be one of:");
            unique_games
                .iter()
                .flat_map(get_name_from_node)
                .for_each(|name| info!("       {name}"));

            SortOption::Warning
        }
    };

    sort_file(output, &path, sort_option, true);

    Ok(())
}

fn rename_to_game(file_path: &Utf8Path, game_name: &str) -> Result<Utf8PathBuf> {
    let file_name = expect_file_name(file_path)?;
    let new_file_name = match file_path.extension() {
        Some(ext) => game_name.to_string() + "." + ext,
        None => game_name.to_string(),
    };
    if file_name != new_file_name {
        debug!("renaming {file_path} to {new_file_name}");
        let result = rename_file_if_possible(file_path, &new_file_name);
        match &result {
            Ok(new_path) => info!("{new_path} (renamed from {file_path})"),
            Err(err) => warn!("could not rename '{file_path}' to '{new_file_name}' - {err}"),
        }
        result
    } else {
        Ok(file_path.to_path_buf())
    }
}
