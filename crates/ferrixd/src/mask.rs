//! Glob mask matching for bans (channel `+b`, server K-Lines).
//!
//! Masks use `*` (matches any run, including empty) and `?` (matches exactly one
//! character). Matching is ASCII-case-insensitive, which is correct for the
//! `user@host` portion; nick folding is applied by callers where it matters.

/// Match `text` against glob `pattern`. Case-insensitive (ASCII).
///
/// Uses the classic linear-time backtracking algorithm (no recursion, no
/// allocation beyond the char vectors), so a hostile pattern cannot blow the
/// stack or hang.
#[must_use]
pub fn matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || eq_ci(p[pi], t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star {
            // Backtrack: let the last `*` swallow one more character.
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn eq_ci(a: char, b: char) -> bool {
    a.eq_ignore_ascii_case(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_case() {
        assert!(matches("abc", "abc"));
        assert!(matches("AbC", "aBc"));
        assert!(!matches("abc", "abd"));
    }

    #[test]
    fn wildcards() {
        assert!(matches("*", ""));
        assert!(matches("*", "anything"));
        assert!(matches("a*c", "ac"));
        assert!(matches("a*c", "abbbc"));
        assert!(!matches("a*c", "abbb"));
        assert!(matches("a?c", "abc"));
        assert!(!matches("a?c", "ac"));
    }

    #[test]
    fn hostmask_patterns() {
        assert!(matches("*!*@1.2.3.4", "nick!user@1.2.3.4"));
        assert!(matches("bad*!*@*", "badguy!x@host"));
        assert!(!matches("*!*@1.2.3.4", "nick!user@1.2.3.5"));
        assert!(matches("*!*@*.evil.example", "n!u@host.evil.example"));
    }

    #[test]
    fn trailing_stars_and_backtrack() {
        assert!(matches("a*", "a"));
        assert!(matches("*a*b*", "xxaxxbxx"));
        assert!(!matches("*a*b*c", "xxaxxbxx"));
    }
}
