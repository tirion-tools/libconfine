//! Allowlist files: one syscall name per line; `#` starts a comment (whole line or trailing); blank
//! lines are ignored.

/// The syscall names of `text`, in file order (duplicates are kept; the filter compiler refuses them).
pub fn parse(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter_map(|l| l.split('#').next().map(str::trim).filter(|s| !s.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn comments_blank_lines_and_whitespace() {
        let text = "# header\n\nread\n  write  # fd 1 only\n#close\n\tmmap\t\n   # indented comment\nbrk#x\n";
        assert_eq!(
            parse(text).collect::<Vec<_>>(),
            ["read", "write", "mmap", "brk"]
        );
    }

    #[test]
    fn empty_and_comment_only() {
        assert_eq!(parse("").count(), 0);
        assert_eq!(parse("# nothing\n\n   \n#\n").count(), 0);
    }

    #[test]
    fn keeps_duplicates_and_order() {
        assert_eq!(parse("b\na\nb\n").collect::<Vec<_>>(), ["b", "a", "b"]);
    }
}
