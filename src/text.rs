//! Text helpers shared by the show renderers.

/// Left-aligned columns separated by two spaces, header underlined
/// with dashes, trailing whitespace trimmed — the `tabulate` default
/// the VyOS op-mode scripts print.
pub(crate) fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }
    let mut out = String::new();
    let mut line = |cells: &[String]| {
        let mut parts = Vec::new();
        for (i, cell) in cells.iter().enumerate() {
            parts.push(format!("{cell:<width$}", width = widths[i]));
        }
        let joined = parts.join("  ");
        out.push_str(joined.trim_end());
        out.push('\n');
    };
    line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    line(&widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>());
    for row in rows {
        line(row);
    }
    out
}

/// vyos seconds_to_human with the default empty separator:
/// `93784` → `1d2h3m4s`.
pub(crate) fn seconds_to_human(mut secs: u64) -> String {
    const UNITS: [(u64, &str); 5] = [
        (60 * 60 * 24 * 7, "w"),
        (60 * 60 * 24, "d"),
        (60 * 60, "h"),
        (60, "m"),
        (1, "s"),
    ];
    let mut out = String::new();
    for (factor, suffix) in UNITS {
        let amount = secs / factor;
        secs %= factor;
        if amount > 0 {
            out.push_str(&format!("{amount}{suffix}"));
        }
    }
    if out.is_empty() {
        out.push_str("0s");
    }
    out
}
