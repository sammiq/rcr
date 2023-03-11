use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, DatabaseName, OpenFlags, Row};

/// opens an existing database, create a new one if not exist
pub fn open_or_create_writable_db(db_name: &str) -> Result<Connection> {
    match open_writable_db(db_name) {
        Ok(connection) => Ok(connection),
        Err(_) => create_db(db_name),
    }
}

/// opens an existing database, error if not exist
pub fn open_writable_db(db_name: &str) -> Result<Connection> {
    match Connection::open_with_flags(db_name, OpenFlags::SQLITE_OPEN_READ_WRITE) {
        Ok(connection) => check_db_read_write(connection),
        Err(_) => create_db(db_name),
    }
}

pub fn create_db(db_name: &str) -> Result<Connection> {
    let connection = check_db_read_write(
        Connection::open_with_flags(db_name, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)
            .context("Unable to create database in current directory")?,
    )?;

    //drop all existing tables, clearing all existing data
    connection
        .execute("DROP TABLE IF EXISTS files", [])
        .context("Unable to initialize database in current directory")?;

    connection
        .execute("DROP INDEX IF EXISTS idx_game_name", [])
        .context("Unable to initialize database in current directory")?;

    connection
        .execute("DROP INDEX IF EXISTS idx_file_hash", [])
        .context("Unable to initialize database in current directory")?;

    connection
        .execute("DROP TABLE IF EXISTS reference", [])
        .context("Unable to initialize database in current directory")?;

    connection
        .execute("DROP TABLE IF EXISTS metadata", [])
        .context("Unable to initialize database in current directory")?;

    //create table for dat-file entries
    connection
        .execute(
            "CREATE TABLE metadata (
                id INTEGER NOT NULL PRIMARY KEY,
                dat_name TEXT NOT NULL,
                dat_description TEXT NOT NULL,
                dat_version TEXT NOT NULL,
                init_date TEXT NOT NULL,
                hash_method TEXT NOT NULL
            )",
            [],
        )
        .context("Unable to initialize database in current directory")?;

    //create table for dat-file entries
    connection
        .execute(
            "CREATE TABLE reference (
                id INTEGER NOT NULL PRIMARY KEY,
                game_name TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL
            )",
            [],
        )
        .context("Unable to initialize database in current directory")?;

    connection
        .execute("CREATE INDEX idx_file_hash ON reference (file_hash)", [])
        .context("Unable to initialize database in current directory")?;

    connection
        .execute("CREATE INDEX idx_game_name ON reference (game_name)", [])
        .context("Unable to initialize database in current directory")?;

    //create table for filesystem entries
    connection
        .execute(
            "CREATE TABLE files (
                id INTEGER NOT NULL PRIMARY KEY,
                hash TEXT NOT NULL,
                file_name TEXT NOT NULL,
                reference_id INTEGER REFERENCES reference(id)
            )",
            [],
        )
        .context("Unable to initialize database in current directory")?;

    //create table to map filesystem entries to reference
    connection
        .execute(
            "CREATE TABLE file_reference (
                file_id INTEGER NOT NULL REFERENCES reference(id),
                reference_id INTEGER NOT NULL REFERENCES reference(id)
            )",
            [],
        )
        .context("Unable to initialize database in current directory")?;

    Ok(connection)
}

fn check_db_read_write(connection: Connection) -> Result<Connection> {
    if connection
        .is_readonly(DatabaseName::Main)
        .expect("should not fail during sqlite request")
    {
        Err(anyhow!("Could not open database for writing"))
    } else {
        Ok(connection)
    }
}

pub fn add_metadata_entry(connection: &Connection, method: &str, name: &str, description: &str, version: &str) -> Result<()> {
    let now = chrono::Local::now().to_rfc3339();
    connection
        .execute(
            "INSERT INTO metadata (dat_name, dat_description, dat_version, init_date, hash_method) VALUES (?1, ?2, ?3, ?4, ?5)",
            (name, description, version, now, method),
        )
        .context("Unable to add metadata in current database")?;

    Ok(())
}

#[derive(Clone, Debug)]
pub struct ReferenceEntry {
    pub id: i64,
    pub game_name: String,
    pub file_hash: String,
    pub file_name: String,
    pub file_size: i64,
}

pub fn add_reference_entry(connection: &Connection, game_name: &str, hash: &str, name: &str, size: &str) -> Result<()> {
    connection
        .execute(
            "INSERT INTO reference (game_name, file_hash, file_name, file_size) VALUES (?1, ?2, ?3, ?4)",
            (game_name, hash, name, size),
        )
        .context("Unable to add reference data in current database")?;

    Ok(())
}

pub fn find_reference_by_id(connection: &Connection, id: i64) -> Result<ReferenceEntry> {
    let mut statement =
        connection.prepare("SELECT id, game_name, file_hash, file_name, file_size FROM reference WHERE id = :id")?;
    let result = statement.query_row(&[(":id", &id)], row_entry);
    result.context("failed to convert result")
}

pub fn find_references_by_hash(connection: &Connection, hash: &str) -> Result<Vec<ReferenceEntry>> {
    let mut statement =
        connection.prepare("SELECT id, game_name, file_hash, file_name, file_size FROM reference WHERE file_hash = :hash")?;
    let result: Result<Vec<ReferenceEntry>, rusqlite::Error> = statement.query(&[(":hash", hash)])?.mapped(row_entry).collect();
    result.context("failed to convert result")
}

pub fn find_references_by_name(connection: &Connection, file_name: &str) -> Result<Vec<ReferenceEntry>> {
    let mut statement =
        connection.prepare("SELECT id, game_name, file_hash, file_name, file_size FROM reference WHERE file_name = :name")?;
    let result: Result<Vec<ReferenceEntry>, rusqlite::Error> =
        statement.query(&[(":name", file_name)])?.mapped(row_entry).collect();
    result.context("failed to convert result")
}

fn row_entry(row: &Row) -> Result<ReferenceEntry, rusqlite::Error> {
    Ok(ReferenceEntry {
        id: row.get(0)?,
        game_name: row.get(1)?,
        file_hash: row.get(2)?,
        file_name: row.get(3)?,
        file_size: row.get(4)?,
    })
}

pub fn add_file_entry(connection: &Connection, hash: &str, file_name: &str, reference_id: Option<i64>) -> Result<()> {
    connection
        .execute(
            "INSERT INTO files (hash, file_name, reference_id) VALUES (?1, ?2, ?3)",
            (hash, file_name, reference_id),
        )
        .context("Unable to add file data in current database")?;

    Ok(())
}
