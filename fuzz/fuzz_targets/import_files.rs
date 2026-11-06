#![no_main]

//! The readers of uploaded import files (`POST /imports`): CSV in its encodings and
//! delimiters, xlsx through the zip central directory reader and `calamine`, and the
//! refusal of xls and ods. The first octet picks the file name the upload carries (the
//! readers detect the format from the content, the name is only a hint), the rest is the
//! file. The readers run with the limits of a real installation; whatever they return
//! stays within them, so a file that parses never holds more sheets, rows, columns, cells
//! or text than the limits allow. Run it with an allocation limit, for example
//! `cargo +nightly fuzz run import_files -- -rss_limit_mb=2048 -malloc_limit_mb=1024`,
//! so that an allocation sized by the input rather than by the limits is reported.

use std::sync::Once;

use libfuzzer_sys::fuzz_target;
use tenko_ipam::import::read::{ReadLimits, read_file};

/// The xlsx reader runs `calamine` inside `catch_unwind` and answers a panic there with
/// "the workbook structure is damaged" (its overflow checks fire on some cell references in
/// a build that has them). libFuzzer's panic hook aborts at every panic, caught or not, so
/// this target lets a panic raised in `calamine`'s own code unwind to that catch and keeps
/// the abort for every other panic, Tenko's included.
fn let_calamine_panics_unwind() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let abort = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let in_calamine = info.location().is_some_and(|location| {
                location.file().replace('\\', "/").contains("/calamine-")
            });
            if !in_calamine {
                abort(info);
            }
        }));
    });
}

const NAMES: [&str; 6] = [
    "plan.csv",
    "plan.xlsx",
    "plan.xls",
    "plan.ods",
    "plan",
    "192.0.2.0.csv",
];

fuzz_target!(|data: &[u8]| {
    let_calamine_panics_unwind();
    let Some((&pick, bytes)) = data.split_first() else {
        return;
    };
    let name = NAMES[usize::from(pick) % NAMES.len()];
    let limits = ReadLimits::default();
    let Ok(file) = read_file(name, bytes, &limits) else {
        return;
    };
    assert!(file.sheets.len() <= limits.max_sheets);
    let mut cells = 0usize;
    let mut text = 0usize;
    for sheet in &file.sheets {
        assert!(sheet.rows.len() <= limits.max_rows);
        for row in &sheet.rows {
            assert!(row.len() <= limits.max_columns);
            cells += row.len();
            text += row.iter().map(|cell| cell.text.len()).sum::<usize>();
        }
    }
    assert!(cells <= limits.max_cells);
    assert!(text <= limits.max_text_bytes);
});
