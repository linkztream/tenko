//! The language tag of a pack: a well-formed BCP 47 tag (RFC 5646) in its canonical case.
//!
//! A pack is named by `language[-extlang][-script][-region][-variant...][-extension...][-x-private]`
//! with a primary language subtag of two or three letters: `fr`, `pt-BR`, `zh-Hant-TW`,
//! `sr-Latn-RS`, `de-CH-1996`, `ar-XB` (the pseudo right-to-left locale of the tests). The
//! language and extended language are lower case, the script is title case, the region upper
//! case and everything after it lower case, so one language has one name. Grandfathered and
//! irregular tags are refused. Whether the subtags are registered with IANA is not checked.

/// Checks a tag.
///
/// # Errors
///
/// An English explanation; when only the case is wrong, it names the canonical form.
pub fn check(tag: &str) -> Result<(), String> {
    let canonical = canonical(tag)?;
    if canonical == tag {
        Ok(())
    } else {
        Err(format!(
            "the tag is not in canonical case, write {canonical}"
        ))
    }
}

/// The canonical case of a well-formed tag.
///
/// # Errors
///
/// An English explanation when the tag is not well formed.
pub fn canonical(tag: &str) -> Result<String, String> {
    if tag.is_empty() || tag.len() > 64 {
        return Err("a language tag has 2 to 64 characters".to_owned());
    }
    if !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("a language tag has only letters, digits and hyphens".to_owned());
    }
    let subtags: Vec<&str> = tag.split('-').collect();
    if subtags.iter().any(|s| s.is_empty() || s.len() > 8) {
        return Err("every subtag has 1 to 8 characters".to_owned());
    }
    let mut out: Vec<String> = Vec::with_capacity(subtags.len());
    let i = head(&subtags, &mut out)?;
    let i = tail(&subtags, i, &mut out)?;
    if i < subtags.len() {
        return Err(format!(
            "the subtag {} is out of place or malformed",
            subtags[i]
        ));
    }
    Ok(out.join("-"))
}

fn alpha(s: &str, n: std::ops::RangeInclusive<usize>) -> bool {
    n.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphabetic())
}

/// The language, extended languages, script and region; the answer is the next index.
fn head(subtags: &[&str], out: &mut Vec<String>) -> Result<usize, String> {
    let language = subtags[0];
    if !alpha(language, 2..=3) {
        return Err("the primary language subtag has two or three letters".to_owned());
    }
    out.push(language.to_ascii_lowercase());
    let mut i = 1;
    let mut extlangs = 0;
    while i < subtags.len() && extlangs < 3 && alpha(subtags[i], 3..=3) {
        out.push(subtags[i].to_ascii_lowercase());
        i += 1;
        extlangs += 1;
    }
    if i < subtags.len() && alpha(subtags[i], 4..=4) {
        let script = subtags[i].to_ascii_lowercase();
        let mut title = script[..1].to_ascii_uppercase();
        title.push_str(&script[1..]);
        out.push(title);
        i += 1;
    }
    if i < subtags.len() {
        let s = subtags[i];
        if alpha(s, 2..=2) {
            out.push(s.to_ascii_uppercase());
            i += 1;
        } else if s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()) {
            out.push(s.to_owned());
            i += 1;
        }
    }
    Ok(i)
}

/// Variants, extensions and the private-use part from index `i`; the answer is the next index.
fn tail(subtags: &[&str], mut i: usize, out: &mut Vec<String>) -> Result<usize, String> {
    let mut variants: Vec<String> = Vec::new();
    while i < subtags.len() {
        let s = subtags[i];
        let variant =
            (5..=8).contains(&s.len()) || (s.len() == 4 && s.as_bytes()[0].is_ascii_digit());
        if !variant {
            break;
        }
        let lower = s.to_ascii_lowercase();
        if variants.contains(&lower) {
            return Err(format!("the variant {lower} appears twice"));
        }
        variants.push(lower.clone());
        out.push(lower);
        i += 1;
    }
    let mut singletons: Vec<u8> = Vec::new();
    while i < subtags.len() && subtags[i].len() == 1 {
        let singleton = subtags[i].as_bytes()[0].to_ascii_lowercase();
        if singleton == b'x' {
            break;
        }
        if singletons.contains(&singleton) {
            return Err(format!(
                "the extension {} appears twice",
                char::from(singleton)
            ));
        }
        singletons.push(singleton);
        out.push(char::from(singleton).to_string());
        i += 1;
        let start = i;
        while i < subtags.len() && subtags[i].len() >= 2 {
            out.push(subtags[i].to_ascii_lowercase());
            i += 1;
        }
        if i == start {
            return Err("an extension needs at least one subtag of 2 to 8 characters".to_owned());
        }
    }
    if i < subtags.len() && subtags[i].eq_ignore_ascii_case("x") {
        out.push("x".to_owned());
        i += 1;
        if i == subtags.len() {
            return Err("a private-use part needs at least one subtag".to_owned());
        }
        while i < subtags.len() {
            out.push(subtags[i].to_ascii_lowercase());
            i += 1;
        }
    }
    Ok(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_tags_in_canonical_case_pass() {
        for tag in [
            "fr",
            "pt-BR",
            "zh-Hant",
            "zh-Hant-TW",
            "sr-Latn-RS",
            "es-419",
            "de-CH-1996",
            "sl-rozaj-biske",
            "ar-XB",
            "en-XA",
            "en-u-nu-latn",
            "en-x-pseudo",
            "zh-yue-HK",
            "fil",
        ] {
            assert_eq!(check(tag), Ok(()), "{tag}");
            assert!(tenko_core::i18n::is_language_tag(tag), "{tag}");
        }
    }

    #[test]
    fn the_case_is_canonical() {
        assert_eq!(canonical("PT-br").as_deref(), Ok("pt-BR"));
        assert_eq!(canonical("ZH-HANT-tw").as_deref(), Ok("zh-Hant-TW"));
        assert!(check("pt-br").is_err_and(|e| e.contains("pt-BR")));
    }

    #[test]
    fn malformed_tags_are_refused() {
        for tag in [
            "",
            "e",
            "english",
            "en_US",
            "en-",
            "-en",
            "en--US",
            "en-US-US",
            "en-toolongsubtag",
            "en-a",
            "en-x",
            "en-1996-1996",
            "en-a-bbb-a-ccc",
            "i-klingon",
            "12",
            "en-US-é",
        ] {
            assert!(canonical(tag).is_err(), "{tag}");
        }
    }
}
