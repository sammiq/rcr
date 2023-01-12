rcr: a simple rom auditing tool in Rust
=======================================

This tool uses logiqx xml format dat files, as provided by your friendly preservation site, for verifying your own dumps
against known good versions of the same software.

It supports stand-alone files and sets in zip files and loading parameters from an `.env` file in the current directory.

History
-------

While looking around for a simple verification tool for rom/iso verification, I found very few that were not built
specifically for Windows.

After having written `check-roms` in Go, I thought I would port at least the basics to Rust.

NOTE: This is probably NOT a good place to look for decent Rust code as this is literally the first thing I've ever
written in the language; really, look elsewhere.

Installation
------------

Prebuild binaries are available on the [Releases](https://github.com/sammiq/rcr/releases) page for Linux, Mac OS and Windows.

Wildcards are supported in Windows by the use of the [wild](https://docs.rs/crate/wild/latest) crate.

Building
--------

You need a working [Rust](https://www.rust-lang.org) installation (I use Rust 1.66 on Ubuntu Linux 22.04).

Build the tool with:

    cargo build --release

IMPORTANT: Performance will be *terrible* without compiling for release, the SHA hash code is incredibly slow when unoptimised.

Usage
-----
    rcr [OPTIONS] --dat-file <DAT_FILE> <FILES>...

    ARGS:
        <FILES>...    list of files to check against reference dat file
    
    OPTIONS:
        -d, --dat-file <DAT_FILE>  name of the dat file to use as reference [env: RCR_DATFILE=]
        -e, --exclude <EXCLUDE>    comma seperated list of suffixes to exclude when scanning,
                                   overrides any files on command line [env: RCR_EXCLUDE=]
        -f, --fast                 fast match mode for single rom games,
                                   may show incorrect names if multiple identical hashes [env: RCR_FAST=]
        -m, --method <METHOD>      method to use for matching reference entries
                                   (note: Sha256 is not well supported in dat files from many sources)
                                   [env: RCR_METHOD=] [default: sha1] [possible values: sha256, sha1, md5]
        -r, --rename               rename mismatched files to reference filename if unambiguous [env: RCR_RENAME=]
        -v, --verbose...           verbose mode, add more of these for more information [env: RCR_VERBOSE=]
        -w, --workers <WORKERS>    number of threads to use for processing, may increase performance
                                   (note: depends on storage bandwidth, more may be slower than fewer)
                                   [env: RCR_WORKERS=] [default: 1]
        -h, --help                 Print help information
        -V, --version              Print version information


Limitations
-----------

- Supports only UTF-8 files and paths, as I use the [camino](https://docs.rs/crate/camino/latest) crate and it matches my use-case.
- Does not rename misnamed files inside zip files.
- Does not support compression formats other than zip.
- Does not read elements other than `<rom>` inside `<game>` from dat file (I  am yet to find a file containing others).
