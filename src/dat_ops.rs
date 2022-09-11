use log::debug;
use roxmltree::{Document, Node};

pub fn is_game_node(n: &Node) -> bool {
    n.tag_name().name() == "game"
}

pub fn is_rom_node(n: &Node) -> bool {
    n.tag_name().name() == "rom"
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
