use crate::dat_ops::*;
use crate::db::*;
use crate::extensions::*;
use std::fs;

use crate::hash::MatchMethod;
use anyhow::{Context, Result};
use camino::Utf8Path;
use log::{info, trace, warn};
use roxmltree::{Document, Node};
use rusqlite::{Connection, Transaction, TransactionBehavior};

pub fn read_dat_to_db(db_name: &str, dat_file: &Utf8Path, wanted_method: MatchMethod) -> Result<(Connection, MatchMethod)> {
    trace!("reading dat file {}", dat_file);
    //read in the xml to buffer, roxmltree will reference into this buffer for the document and all nodes
    let df_buffer = fs::read_to_string(dat_file).context("Unable to read reference dat file")?;
    let df_xml = Document::parse(df_buffer.as_str()).context("Unable to parse reference dat file")?;
    info!("dat file {} read successfully", dat_file);

    //ensure that the dat file will support this usage
    let method = sanity_check_match_method(&df_xml, wanted_method)?;
    if method != wanted_method {
        warn!("matching files using {} after checking, as reference dat file is missing {}", method, wanted_method);
    }
    let hash_method = method.to_string();

    let mut connection = create_db(db_name)?;
    save_metadata_to_db(&connection, &df_xml, &hash_method)?;
    save_reference_data_to_db(&mut connection, &df_xml, &hash_method)?;

    Ok((connection, method))
}

pub fn save_metadata_to_db(connection: &Connection, df_xml: &Document, method: &str) -> Result<()> {
    let header_node = df_xml
        .root_element()
        .children()
        .find(is_header_node)
        .context("could not find header node of dat file")?;

    let name = header_node
        .children()
        .find(|n| is_node_name(n, "name"))
        .and_then(|n| n.text())
        .context("could not find name metadata")?;
    let description = header_node
        .children()
        .find(|n| is_node_name(n, "description"))
        .and_then(|n| n.text())
        .context("could not find description metadata")?;
    let version = header_node
        .children()
        .find(|n| is_node_name(n, "version"))
        .and_then(|n| n.text())
        .context("could not find version metadata")?;

    add_metadata_entry(connection, method, name, description, version)
}

pub fn save_reference_data_to_db(connection: &mut Connection, df_xml: &Document, method: &str) -> Result<()> {
    let tx = Transaction::new(connection, TransactionBehavior::Exclusive)?;

    df_xml
        .root_element() //datafile
        .children()
        .filter(is_game_node)
        .for_each(|ref game_node| {
            add_rom_entries(&tx, method, game_node)
                .if_err(|error| warn!("could not process game node, skipping; error was '{error}'"));
        });

    tx.commit()
        .context("could not commit transaction on database while saving reference information")
}

pub fn add_rom_entries(connection: &Connection, method: &str, game_node: &Node) -> Result<()> {
    let game_name = get_name_from_node(game_node).context("could not find name on game node")?;

    game_node.children().filter(is_rom_node).for_each(|ref rom_node| {
        add_rom_entry(connection, method, game_name, rom_node)
            .if_err(|error| warn!("could not add rom entries for '{game_name}', skipping; error was '{error}'"));
    });

    Ok(())
}

pub fn add_rom_entry(connection: &Connection, method: &str, game_name: &str, rom_node: &Node) -> Result<()> {
    let hash = rom_node.attribute(method).context("could not find hash metadata")?;
    let name = rom_node.attribute("name").context("could not find name metadata")?;
    let size = rom_node.attribute("size").context("could not find size metadata")?;

    add_reference_entry(connection, game_name, hash, name, size)
}
