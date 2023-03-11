use crate::hash::*;

use anyhow::{ensure, Result};
use log::debug;
use roxmltree::{Document, Node};

pub fn is_header_node(n: &Node) -> bool {
    is_node_name(n, "header")
}

pub fn is_game_node(n: &Node) -> bool {
    is_node_name(n, "game")
}

pub fn is_rom_node(n: &Node) -> bool {
    is_node_name(n, "rom")
}

pub fn is_node_name(n: &Node, name: &str) -> bool {
    n.tag_name().name() == name
}

pub fn get_hash_from_rom_node(node: &Node, method: &str) -> Option<String> {
    node.attribute(method).map(str::to_ascii_lowercase)
}

pub fn get_name_from_node<'a>(node: &'a Node) -> Option<&'a str> {
    node.attribute("name")
}

pub fn find_rom_nodes_by_hash<'a>(
    df_xml: &'a Document,
    method: &str,
    hash_string: &str,
    first_match_only: bool,
) -> Vec<Node<'a, 'a>> {
    debug!("looking up '{hash_string}' using method '{method}'");
    if first_match_only {
        df_xml
            .descendants()
            .filter(is_rom_node)
            .find(|n| get_hash_from_rom_node(n, method) == Some(hash_string.to_ascii_lowercase()))
            .map(|n| vec![n])
            .unwrap_or_default()
    } else {
        df_xml
            .descendants()
            .filter(is_rom_node)
            .filter(|n| get_hash_from_rom_node(n, method) == Some(hash_string.to_ascii_lowercase()))
            .collect()
    }
}

pub fn sanity_check_match_method(df_xml: &Document, method: MatchMethod) -> Result<MatchMethod> {
    sanity_check_match_method_inner(df_xml, method, 0)
}

fn sanity_check_match_method_inner(df_xml: &Document, method: MatchMethod, recursion: u8) -> Result<MatchMethod> {
    debug!("sanity checking {method}...");
    //check whether this file has those methods
    if df_xml
        .descendants()
        .filter(is_rom_node)
        .any(|n| get_hash_from_rom_node(&n, &method.to_string()).is_some())
    {
        debug!("sanity check {method} passed");
        Ok(method)
    } else {
        debug!("sanity check {method} failed");
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
