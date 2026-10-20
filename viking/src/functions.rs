use crate::{elf, repo};
use anyhow::{bail, ensure, Context, Result};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Matching,
    NonMatchingMinor,
    NonMatchingMajor,
    NotDecompiled,
    Wip,
    Library,
}

impl Status {
    fn from_builtin_code(code: char) -> Option<Status> {
        match code {
            'm' => Some(Status::NonMatchingMinor),
            'M' => Some(Status::NonMatchingMajor),
            'O' => Some(Status::Matching),
            'U' => Some(Status::NotDecompiled),
            'W' => Some(Status::Wip),
            'L' => Some(Status::Library),
            _ => None,
        }
    }

    fn builtin_code(&self) -> char {
        match self {
            Status::Matching => 'O',
            Status::NonMatchingMinor => 'm',
            Status::NonMatchingMajor => 'M',
            Status::NotDecompiled => 'U',
            Status::Wip => 'W',
            Status::Library => 'L',
        }
    }

    pub fn description(&self) -> &'static str {
        match &self {
            Status::Matching => "matching",
            Status::NonMatchingMinor => "non-matching (minor)",
            Status::NonMatchingMajor => "non-matching (major)",
            Status::NotDecompiled => "not decompiled",
            Status::Wip => "WIP",
            Status::Library => "library function",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Info {
    pub addr: u64,
    pub size: u32,
    pub name: String,
    pub status: Status,
    /// Project-specific status code from the CSV (see `StatusCodes`), if one was used.
    pub status_code: Option<char>,
}

impl Info {
    pub fn is_decompiled(&self) -> bool {
        !matches!(self.status, Status::NotDecompiled | Status::Library)
    }

    pub fn get_start(&self) -> u64 {
        self.addr | ADDRESS_BASE
    }

    pub fn get_end(&self) -> u64 {
        self.get_start() + self.size as u64
    }
}

/// Extra status codes declared in the `[status_codes]` table of tools/config.toml.
/// Each one is an alias of a built-in code.
pub type StatusCodes = FxHashMap<char, Status>;

pub fn parse_status_codes<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<StatusCodes> {
    let mut codes = StatusCodes::default();
    for (code, target) in entries {
        let mut chars = code.chars();
        let (Some(code), None) = (chars.next(), chars.next()) else {
            bail!("status code {code:?} must be a single character");
        };
        ensure!(
            Status::from_builtin_code(code).is_none(),
            "status code {code:?} is a built-in code and cannot be redefined"
        );
        let mut chars = target.chars();
        let status = match (chars.next(), chars.next()) {
            (Some(target), None) => Status::from_builtin_code(target),
            _ => None,
        }
        .with_context(|| {
            format!("status code {code:?} must alias one of the built-in codes O, m, M, U, W, L")
        })?;
        codes.insert(code, status);
    }
    Ok(codes)
}

/// Returns the extra status codes declared in tools/config.toml.
pub fn get_status_codes() -> Result<StatusCodes> {
    match &repo::get_config().status_codes {
        Some(entries) => parse_status_codes(
            entries
                .iter()
                .map(|(code, target)| (code.as_str(), target.as_str())),
        )
        .context("invalid [status_codes] in tools/config.toml"),
        None => Ok(StatusCodes::default()),
    }
}

pub const CSV_HEADER: &[&str] = &["Address", "Quality", "Size", "Name"];
pub const ADDRESS_BASE: u64 = 0x71_0000_0000;

fn parse_base_16(value: &str) -> Result<u64> {
    if let Some(stripped) = value.strip_prefix("0x") {
        Ok(u64::from_str_radix(stripped, 16)?)
    } else {
        Ok(u64::from_str_radix(value, 16)?)
    }
}

pub fn parse_address(value: &str) -> Result<u64> {
    Ok(parse_base_16(value)? - ADDRESS_BASE)
}

fn parse_function_csv_entry(record: &csv::StringRecord, extra_codes: &StatusCodes) -> Result<Info> {
    ensure!(record.len() == 4, "invalid record");

    let addr = parse_address(&record[0])?;
    let status_code = record[1].chars().next();
    let size = record[2].parse::<u32>()?;
    let decomp_name = record[3].to_string();

    let (status, status_code) = match status_code {
        Some(code) => match Status::from_builtin_code(code) {
            Some(status) => (status, None),
            None => match extra_codes.get(&code) {
                Some(status) => (status.clone(), Some(code)),
                None => bail!("unexpected status code: {}", code),
            },
        },
        None => bail!("missing status code"),
    };

    Ok(Info {
        addr,
        size,
        name: decomp_name,
        status,
        status_code,
    })
}

fn check_for_duplicate_names(functions: &[Info], num_names: usize) -> Result<()> {
    let mut known_names = HashSet::with_capacity(num_names);
    let mut duplicates = Vec::new();

    for entry in functions {
        if entry.is_decompiled() && entry.name.is_empty() {
            bail!(
                "function at {:016x} is marked as O/M/m but has an empty name",
                entry.get_start()
            );
        }

        if !entry.name.is_empty() && !known_names.insert(&entry.name) {
            duplicates.push(&entry.name);
        }
    }

    if !duplicates.is_empty() {
        bail!("found duplicates: {:#?}", duplicates);
    }

    Ok(())
}

fn check_for_overlapping_functions(functions: &[Info]) -> Result<()> {
    for pair in functions.windows(2) {
        let first = &pair[0];
        let second = &pair[1];

        ensure!(
            first.get_start() < second.get_start() && first.get_end() <= second.get_start(),
            "overlapping functions: {:016x} - {:016x} and {:016x} - {:016x}",
            first.get_start(),
            first.get_end(),
            second.get_start(),
            second.get_end(),
        );
    }

    Ok(())
}

/// Returns a Vec of all functions that are listed in the specified CSV.
pub fn get_functions_for_path(csv_path: &Path, extra_codes: &StatusCodes) -> Result<Vec<Info>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .quoting(false)
        .from_path(csv_path)?;

    // We build the result array manually without using csv iterators for performance reasons.
    let mut result = Vec::with_capacity(110_000);
    let mut record = csv::StringRecord::new();
    let mut line_number = 1;
    let mut num_names = 0;
    if reader.read_record(&mut record)? {
        // Verify that the CSV has the correct format.
        ensure!(record.len() == 4, "invalid record; expected 4 fields");
        ensure!(record == *CSV_HEADER,
            "wrong CSV format; this program only works with the new function list format (added in commit 1d4c815fbae3)"
        );
        line_number += 1;
    }

    while reader.read_record(&mut record)? {
        let entry = parse_function_csv_entry(&record, extra_codes)
            .with_context(|| format!("failed to parse CSV record at line {line_number}"))?;

        if !entry.name.is_empty() {
            num_names += 1;
        }

        result.push(entry);
        line_number += 1;
    }

    check_for_duplicate_names(&result, num_names)?;
    check_for_overlapping_functions(&result)?;

    Ok(result)
}

pub fn write_functions_to_path(
    csv_path: &Path,
    functions: &[Info],
    extra_codes: &StatusCodes,
) -> Result<()> {
    let mut writer = csv::Writer::from_path(csv_path)?;
    writer.write_record(CSV_HEADER)?;

    for function in functions {
        let addr = format!("0x{:016x}", function.get_start());
        // Keep a project-specific code as long as the status it stands for is unchanged.
        let status = match function.status_code {
            Some(code) if extra_codes.get(&code) == Some(&function.status) => code,
            _ => function.status.builtin_code(),
        }
        .to_string();
        let size = format!("{:06}", function.size);
        let name = function.name.clone();
        writer.write_record(&[addr, status, size, name])?;
    }

    Ok(())
}

pub fn get_functions_csv_path(version: Option<&str>) -> PathBuf {
    let mut path = repo::get_repo_root().expect("Failed to get repo root");
    let config_functions_csv = repo::get_config().functions_csv.clone();
    let functions_csv = version
        .map(|s| config_functions_csv.replace("{version}", s))
        .unwrap_or(config_functions_csv);
    path.push(functions_csv);

    path
}

/// Returns a Vec of all known functions in the executable.
pub fn get_functions(version: Option<&str>) -> Result<Vec<Info>> {
    get_functions_for_path(
        get_functions_csv_path(version).as_path(),
        &get_status_codes()?,
    )
}

pub fn write_functions(functions: &[Info], version: Option<&str>) -> Result<()> {
    write_functions_to_path(
        get_functions_csv_path(version).as_path(),
        functions,
        &get_status_codes()?,
    )
}

pub fn make_known_function_map(functions: &[Info]) -> FxHashMap<u64, &Info> {
    let mut known_functions =
        FxHashMap::with_capacity_and_hasher(functions.len(), Default::default());

    for function in functions {
        known_functions.insert(function.addr, function);
    }

    known_functions
}

pub fn make_known_function_name_map(functions: &[Info]) -> FxHashMap<&str, &Info> {
    let mut known_functions =
        FxHashMap::with_capacity_and_hasher(functions.len(), Default::default());

    for function in functions {
        if function.name.is_empty() {
            continue;
        }
        known_functions.insert(function.name.as_str(), function);
    }

    known_functions
}

/// Demangle a C++ symbol.
pub fn demangle_str(name: &str) -> Result<String> {
    if !name.starts_with("_Z") {
        bail!("not an external mangled name");
    }

    let symbol = cpp_demangle::Symbol::new(name)?;
    let options = cpp_demangle::DemangleOptions::new();
    Ok(symbol.demangle(&options)?)
}

pub fn fuzzy_search<'a>(functions: &[&'a Info], name: &str) -> Vec<&'a Info> {
    let exact_match = functions
        .par_iter()
        .find_first(|function| function.name == name);

    if let Some(&exact_match) = exact_match {
        return vec![exact_match];
    }

    // Find all functions whose demangled name contains the specified string.
    // This is more expensive than a simple string comparison, so only do this after
    // we have failed to find an exact match.
    let mut candidates: Vec<&Info> = functions
        .par_iter()
        .filter(|function| {
            demangle_str(&function.name).is_ok_and(|demangled| demangled.contains(name))
                || function.name.contains(name)
        })
        .copied()
        .collect();

    candidates.sort_by_key(|info| info.addr);
    candidates
}

pub fn filter_candidates_by_symtab<'a>(
    candidates: &'a [Info],
    decomp_symtab: &elf::SymbolTableByName,
) -> Vec<&'a Info> {
    candidates
        .iter()
        .filter(|function| decomp_symtab.contains_key(function.name.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extra_codes() -> StatusCodes {
        parse_status_codes([("A", "O"), ("S", "O"), ("w", "W")]).unwrap()
    }

    const CSV: &str = "Address,Quality,Size,Name
0x0000007100000000,O,000016,f0
0x0000007100000010,A,000016,f1
0x0000007100000020,S,000016,f2
0x0000007100000030,w,000016,f3
0x0000007100000040,U,000016,
";

    #[test]
    fn extra_codes_alias_builtin_status() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("functions.csv");
        std::fs::write(&path, CSV).unwrap();

        let functions = get_functions_for_path(&path, &extra_codes()).unwrap();
        let statuses: Vec<_> = functions.iter().map(|f| f.status.clone()).collect();
        assert_eq!(
            statuses,
            [
                Status::Matching,
                Status::Matching,
                Status::Matching,
                Status::Wip,
                Status::NotDecompiled
            ]
        );
    }

    #[test]
    fn unknown_code_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("functions.csv");
        std::fs::write(&path, CSV).unwrap();

        let err = get_functions_for_path(&path, &StatusCodes::default()).unwrap_err();
        assert!(format!("{err:#}").contains("unexpected status code: A"));
    }

    #[test]
    fn extra_codes_survive_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("functions.csv");
        std::fs::write(&path, CSV).unwrap();
        let codes = extra_codes();

        let functions = get_functions_for_path(&path, &codes).unwrap();
        write_functions_to_path(&path, &functions, &codes).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), CSV);
    }

    #[test]
    fn changed_status_falls_back_to_builtin_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("functions.csv");
        std::fs::write(&path, CSV).unwrap();
        let codes = extra_codes();

        let mut functions = get_functions_for_path(&path, &codes).unwrap();
        functions[1].status = Status::NonMatchingMajor;
        functions[3].status = Status::Matching;
        write_functions_to_path(&path, &functions, &codes).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("0x0000007100000010,M,000016,f1"));
        assert!(written.contains("0x0000007100000020,S,000016,f2"));
        assert!(written.contains("0x0000007100000030,O,000016,f3"));
    }

    #[test]
    fn invalid_status_codes_are_rejected() {
        assert!(parse_status_codes([("O", "M")]).is_err());
        assert!(parse_status_codes([("AB", "O")]).is_err());
        assert!(parse_status_codes([("A", "X")]).is_err());
        assert!(parse_status_codes([("A", "matching")]).is_err());
    }
}
