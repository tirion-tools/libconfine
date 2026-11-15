//! Allowlist files: one syscall name per line; `#` starts a comment (whole line or trailing); blank
//! lines are ignored.

/// The syscall names of `text`, in file order (duplicates are kept; the filter compiler refuses them).
pub fn parse(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter_map(|l| l.split('#').next().map(str::trim).filter(|s| !s.is_empty()))
}
