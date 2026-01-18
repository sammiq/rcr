rcr: a simple rom auditing tool in Rust
=======================================

This tool uses logiqx xml format dat files, as provided by your friendly preservation site, for verifying your own dumps
against known good versions of the same software.

It supports stand-alone files and sets in zip files and loading parameters from an `.env` file in the current directory.

History
-------

While looking around for a simple verification tool for rom/iso verification, I found very few that were not built specifically for Windows and/or are not command-line based.

My aim with this tool is to provide something reasonably portable and useful as a command-line only tool.

Installation
------------

Prebuild binaries are available on the [Releases](https://github.com/sammiq/rcr/releases) page for Linux and Windows.

Wildcards are supported in Windows by the use of the [wild](https://docs.rs/crate/wild/latest) crate.

Building
--------

You need a recent [Rust](https://www.rust-lang.org) installation (I use Rust 1.91 on Fedora 23).

Build the tool with:

    cargo build --release

IMPORTANT: Performance will be *terrible* without compiling for release, the SHA hash code is incredibly slow without compiler optimization.

Optionally, you may compile with memory-mapped file support by building with the appropriate `feature` enabled:

    cargo build --release --features memmap2

This should give a 5-20% speedup when hashing uncompressed rom files fom the file system, depending on the drive and the file system in use, but will have no impact on compressed file hashing irregardless.

Usage
-----
    Usage: rcr [OPTIONS] --dat-file <DAT_FILE> <FILES>...

    Arguments:
    <FILES>...  list of files to check against reference dat file

    Options:
    -a, --any-contents          count any matches in a zip file as a match, otherwise
                                the file count must match for a partial match
                                [env: RCR_ANY_CONTENTS=]
    -d, --dat-file <DAT_FILE>   name of the dat file to use as reference
                                [env: RCR_DATFILE=]
    -e, --exclude <EXCLUDE>...  comma seperated list of suffixes to exclude when scanning,
                                overrides any files on command line
                                [env: RCR_EXCLUDE=] [default: m3u,dat,txt]
    -F, --fast                  fast match mode for single rom games,
                                may show incorrect names if multiple identical hashes
                                [env: RCR_FAST=]
    -f, --found <FOUND>         which found and matching items to print after scan
                                [env: RCR_FOUND=] [default: all]
                                [possible values: files, sets, all, none]
    -i, --ignore-suffix         ignore the suffix when checking for name match
                                [env: RCR_IGNORE_SUFFIX=]
    -M, --method <METHOD>       default method to use for matching reference entries
                                [env: RCR_METHOD=] [default: sha1]
                                [possible values: sha256, sha1, md5]
    -m, --missing <MISSING>     which missing items to print after scan
                                [env: RCR_MISSING=] [default: all]
                                [possible values: files, sets, all, none]
    -r, --rename                rename mismatched files to reference filename if unambiguous
                                [env: RCR_RENAME=]
    -R, --recurse               recurse into directories specified on command line
                                [env: RCR_RECURSE=]
    -s, --sort <SORT>           sort files into directories based on match status
                                [env: RCR_SORT=] [default: none]
                                [possible values: none, unknown, matched, warning, all]
    -S, --sort-dir <SORT_DIR>   base directory to use when sorting files
                                [env: RCR_SORT=] [default: .]
    -v, --verbose...            verbose mode, add more of these for more information
                                [env: RCR_VERBOSE=]
    -w, --warning <WARNING>     which warning items to print after scan
                                [env: RCR_WARNING=] [default: all]
                                [possible values: files, sets, all, none]
    -W, --workers <WORKERS>     number of threads to use for processing,
                                may decrease performance if I/O bound
                                [env: RCR_WORKERS=] [default: 1]
    -h, --help                  Print help
    -V, --version               Print version



Limitations
-----------

- Supports only UTF-8 files and paths, as I use the [camino](https://docs.rs/crate/camino/latest) crate and it matches my use-case.
- Does not rename misnamed files inside zip files.
- Does not support compression formats other than zip.
- Does not read elements other than `<rom>` inside `<game>` from dat file (I  am yet to find a file containing others).
