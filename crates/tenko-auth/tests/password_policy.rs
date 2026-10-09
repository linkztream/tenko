//! Vectors for the password policy presets (IAM-03, TGL-01; NIST SP 800-63B semantics).
//!
//! Each table row is (policy, password, context, expected violations in order). All
//! passwords are obviously fake.

use tenko_auth::{
    AuthError,
    password::{
        ContextKind, CustomPolicy, PasswordContext, PasswordPolicy, PolicyViolation, normalize,
    },
};

/// The context of most rows. No password below may contain `rjames`, `rowan`, `jameson`,
/// `gateway01` or `tenko` unless the row is about context words.
const CONTEXT: PasswordContext<'static> = PasswordContext {
    user_name: "rjames",
    display_name: Some("Rowan Jameson"),
    host_name: Some("gateway01.lab.test"),
};

const BARE: PasswordContext<'static> = PasswordContext {
    user_name: "",
    display_name: None,
    host_name: None,
};

struct Case {
    name: &'static str,
    policy: PasswordPolicy,
    password: String,
    context: PasswordContext<'static>,
    expected: Vec<PolicyViolation>,
}

fn case(
    name: &'static str,
    policy: &PasswordPolicy,
    password: impl Into<String>,
    expected: &[PolicyViolation],
) -> Case {
    case_in(name, policy, password, CONTEXT, expected)
}

fn case_in(
    name: &'static str,
    policy: &PasswordPolicy,
    password: impl Into<String>,
    context: PasswordContext<'static>,
    expected: &[PolicyViolation],
) -> Case {
    Case {
        name,
        policy: policy.clone(),
        password: password.into(),
        context,
        expected: expected.to_vec(),
    }
}

/// Runs every row and reports all failures together.
fn run(cases: Vec<Case>) {
    let total = cases.len();
    let failures: Vec<String> = cases
        .into_iter()
        .filter_map(|case| {
            let actual = case.policy.check(&case.password, &case.context);
            (actual != case.expected).then(|| {
                format!(
                    "{}: {:?} {:?}\n    expected {:?}\n    actual   {:?}",
                    case.name, case.policy, case.password, case.expected, actual
                )
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {total} vectors failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn too_short(min: usize) -> PolicyViolation {
    PolicyViolation::TooShort { min }
}

fn too_long(max: usize) -> PolicyViolation {
    PolicyViolation::TooLong { max }
}

fn context(kind: ContextKind) -> PolicyViolation {
    PolicyViolation::ContextSpecific { context: kind }
}

const TRIVIAL: PolicyViolation = PolicyViolation::Trivial;
const CONTROL: PolicyViolation = PolicyViolation::InvalidCharacters;
const DIGITS_ONLY: PolicyViolation = PolicyViolation::PinDigitsOnly;
const MISMATCH: PolicyViolation = PolicyViolation::PatternMismatch;

fn custom(min_length: usize, max_length: usize, pattern: Option<&str>) -> PasswordPolicy {
    PasswordPolicy::Custom(CustomPolicy {
        min_length,
        max_length,
        pattern: pattern.map(str::to_owned),
    })
}

/// `count` distinct CJK ideographs, five code points apart so that they form no run.
fn ideographs(count: u32) -> String {
    (0..count)
        .map(|i| char::from_u32(0x4E00 + i * 5).expect("a valid code point"))
        .collect()
}

#[test]
fn standard_vectors() {
    let p = PasswordPolicy::Standard;
    let passphrase = "the quick brown fox jumps over the lazy dog while the sun sets slowly";
    assert!(passphrase.chars().count() >= 64);
    run(vec![
        case("a passphrase", &p, "correct horse battery staple", &[]),
        case(
            "a long passphrase of 64 or more characters",
            &p,
            passphrase,
            &[],
        ),
        case("exactly the minimum", &p, "twelve chars", &[]),
        case("one below the minimum", &p, "tangerine-x", &[too_short(12)]),
        case("empty", &p, "", &[too_short(12)]),
        case("spaces are allowed", &p, "  leading and trailing  ", &[]),
        case(
            "no composition: lower case only",
            &p,
            "alllowercaseletters",
            &[],
        ),
        case(
            "no composition: upper case only",
            &p,
            "ALLUPPERCASELETTERS",
            &[],
        ),
        case("no composition: digits only", &p, "1357924680135", &[]),
        case(
            "no composition: punctuation only",
            &p,
            "!?;:,.-_+*/=~^",
            &[],
        ),
        case(
            "exactly the maximum",
            &p,
            "0123456789".repeat(26)[..256].to_owned(),
            &[],
        ),
        case(
            "one above the maximum",
            &p,
            "0123456789".repeat(26)[..257].to_owned(),
            &[too_long(256)],
        ),
        case(
            "a very long password",
            &p,
            "Lorem ipsum dolor sit amet ".repeat(100),
            &[too_long(256)],
        ),
        case(
            "several violations are all reported",
            &p,
            "A\n",
            &[CONTROL, too_short(12)],
        ),
        case(
            "a product word in a short password",
            &p,
            "tenko",
            &[too_short(12), context(ContextKind::Product)],
        ),
    ]);
}

#[test]
fn pin_vectors() {
    let p = PasswordPolicy::Pin;
    let digits64 = "13572468".repeat(8);
    assert_eq!(digits64.len(), 64);
    run(vec![
        case("a PIN", &p, "4829", &[]),
        case("a PIN with a leading zero", &p, "0827", &[]),
        case("a long PIN", &p, "73920481", &[]),
        case("one below the minimum", &p, "482", &[too_short(4)]),
        case("empty", &p, "", &[too_short(4)]),
        case("a letter", &p, "48a9", &[DIGITS_ONLY]),
        case("a trailing space", &p, "4829 ", &[DIGITS_ONLY]),
        case("a sign", &p, "-4829", &[DIGITS_ONLY]),
        case(
            "letters only and too short",
            &p,
            "xz",
            &[DIGITS_ONLY, too_short(4)],
        ),
        case("a control character", &p, "48\n29", &[CONTROL, DIGITS_ONLY]),
        case(
            "control, not digits and short",
            &p,
            "ab\n",
            &[CONTROL, DIGITS_ONLY, too_short(4)],
        ),
        case("exactly the maximum", &p, digits64.clone(), &[]),
        case(
            "one above the maximum",
            &p,
            format!("{digits64}1"),
            &[too_long(64)],
        ),
        // NFKC: compatibility digits become ASCII digits.
        case(
            "fullwidth digits",
            &p,
            "\u{ff10}\u{ff18}\u{ff12}\u{ff17}",
            &[],
        ),
        case(
            "superscript digits",
            &p,
            "\u{b2}\u{2074}\u{2076}\u{2078}",
            &[],
        ),
        case(
            "fullwidth digits that form a run",
            &p,
            "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}",
            &[TRIVIAL],
        ),
        // Other scripts' digits have no ASCII form under NFKC.
        case(
            "Arabic-Indic digits",
            &p,
            "\u{663}\u{665}\u{667}\u{669}",
            &[DIGITS_ONLY],
        ),
        // Trivial PINs.
        case("repeated digit", &p, "0000", &[TRIVIAL]),
        case("repeated digit, six times", &p, "777777", &[TRIVIAL]),
        case("repeated pair", &p, "1212", &[TRIVIAL]),
        case("repeated triple", &p, "123123", &[TRIVIAL]),
        case("ascending run", &p, "1234", &[TRIVIAL]),
        case("descending run", &p, "4321", &[TRIVIAL]),
        case("a long ascending run", &p, "23456789", &[TRIVIAL]),
        case("not a run: a gap", &p, "1235", &[]),
        case("not a run: a pair swapped", &p, "1243", &[]),
        case("not repeated: one digit differs", &p, "1213", &[]),
        case(
            "a PIN with the digits of the user name",
            &p,
            "52468",
            &[context(ContextKind::UserName)],
        )
        .in_context(PasswordContext {
            user_name: "2468",
            display_name: None,
            host_name: None,
        }),
    ]);
}

impl Case {
    fn in_context(mut self, context: PasswordContext<'static>) -> Self {
        self.context = context;
        self
    }
}

#[test]
fn hardened_vectors() {
    let p = PasswordPolicy::Hardened;
    run(vec![
        case("a passphrase", &p, "correct horse battery staple", &[]),
        case("exactly the minimum", &p, "sixteen letters!", &[]),
        case(
            "one below the minimum",
            &p,
            "fifteen letters",
            &[too_short(16)],
        ),
        case(
            "valid for Standard, short here",
            &p,
            "twelve chars",
            &[too_short(16)],
        ),
        case(
            "exactly the maximum",
            &p,
            "0123456789".repeat(26)[..256].to_owned(),
            &[],
        ),
        case(
            "one above the maximum",
            &p,
            "0123456789".repeat(26)[..257].to_owned(),
            &[too_long(256)],
        ),
        case("trivial", &p, "abcdefghijklmnopqrst", &[TRIVIAL]),
        case(
            "trivial and too short",
            &p,
            "aaaaaaaaaaaa",
            &[too_short(16), TRIVIAL],
        ),
    ]);
}

#[test]
fn custom_vectors() {
    let plain = custom(8, 64, None);
    run(vec![
        case("no pattern", &plain, "validpass", &[]),
        case("exactly the minimum", &plain, "validpas", &[]),
        case("one below the minimum", &plain, "valid12", &[too_short(8)]),
        case(
            "exactly the maximum",
            &plain,
            "0123456789".repeat(7)[..64].to_owned(),
            &[],
        ),
        case(
            "one above the maximum",
            &plain,
            "0123456789".repeat(7)[..65].to_owned(),
            &[too_long(64)],
        ),
        case(
            "context applies to Custom",
            &plain,
            "xxrjamesxx",
            &[context(ContextKind::UserName)],
        ),
        case("trivial applies to Custom", &plain, "aaaaaaaa", &[TRIVIAL]),
    ]);
}

#[test]
fn custom_pattern_vectors() {
    let lower_then_digits = custom(8, 64, Some("[a-z]+[0-9]+"));
    run(vec![
        // The pattern must match the whole normalized password.
        case("pattern: matches", &lower_then_digits, "mango2024", &[]),
        case(
            "pattern: upper case letter",
            &lower_then_digits,
            "Mango2024",
            &[MISMATCH],
        ),
        case(
            "pattern: trailing character",
            &lower_then_digits,
            "mango2024!",
            &[MISMATCH],
        ),
        case(
            "pattern: leading character",
            &lower_then_digits,
            "!mango2024",
            &[MISMATCH],
        ),
        case(
            "pattern: only letters",
            &lower_then_digits,
            "mangoeslots",
            &[MISMATCH],
        ),
        case(
            "pattern: a match in the middle is not enough",
            &lower_then_digits,
            "--mango2024--",
            &[MISMATCH],
        ),
        case(
            "pattern: alternation matches branch one",
            &custom(4, 64, Some("coffee|tea-time")),
            "coffee",
            &[],
        ),
        case(
            "pattern: alternation matches branch two",
            &custom(4, 64, Some("coffee|tea-time")),
            "tea-time",
            &[],
        ),
        case(
            "pattern: alternation is anchored as a whole",
            &custom(4, 64, Some("coffee|tea-time")),
            "tea-time-extra",
            &[MISMATCH],
        ),
        case(
            "pattern: alternation is not anchored per branch",
            &custom(4, 64, Some("coffee|tea-time")),
            "extra-coffee",
            &[MISMATCH],
        ),
        case(
            "pattern: flags",
            &custom(8, 64, Some("(?i)[a-z]+[0-9]+")),
            "Mango2024",
            &[],
        ),
        case(
            "pattern: Perl classes",
            &custom(8, 64, Some(r"\w+-\d{4}")),
            "mango-2024",
            &[],
        ),
        case(
            "pattern is matched against the normalized password",
            &custom(4, 64, Some("[0-9]{6}")),
            "\u{ff11}\u{ff12}\u{ff19}\u{ff14}\u{ff17}\u{ff18}",
            &[],
        ),
        case(
            "pattern with other violations comes last",
            &custom(8, 64, Some("[a-z]+")),
            "ABCDEFG",
            &[too_short(8), TRIVIAL, MISMATCH],
        ),
    ]);
}

#[test]
fn custom_edge_vectors() {
    run(vec![
        case(
            "a pattern that does not compile fails closed",
            &custom(8, 64, Some("(")),
            "whatever-password",
            &[MISMATCH],
        ),
        case(
            "an unbalanced group is not smuggled through the anchor",
            &custom(4, 64, Some("a)(b")),
            "ab-ab-ab",
            &[MISMATCH],
        ),
        // Lengths count characters after NFKC: the ligature is two characters.
        case(
            "a ligature counts as two characters",
            &custom(4, 64, None),
            "\u{fb01}sh",
            &[],
        ),
        case(
            "a ligature does not count once",
            &custom(5, 64, None),
            "\u{fb01}sh",
            &[too_short(5)],
        ),
    ]);
}

#[test]
fn trivial_vectors() {
    let p = PasswordPolicy::Standard;
    run(vec![
        case("one character repeated", &p, "aaaaaaaaaaaa", &[TRIVIAL]),
        case(
            "one character repeated, long",
            &p,
            "b".repeat(20),
            &[TRIVIAL],
        ),
        case("a pair repeated", &p, "abababababab", &[TRIVIAL]),
        case("a triple repeated", &p, "abcabcabcabc", &[TRIVIAL]),
        case("digits repeated", &p, "123123123123", &[TRIVIAL]),
        case("zero and one", &p, "010101010101", &[TRIVIAL]),
        case("case-insensitive: pair", &p, "AbAbAbAbAbAb", &[TRIVIAL]),
        case("case-insensitive: triple", &p, "AbcABCaBCabc", &[TRIVIAL]),
        case(
            "case-insensitive: one character",
            &p,
            "aAaAaAaAaAaA",
            &[TRIVIAL],
        ),
        case("ascending letters", &p, "abcdefghijklmnop", &[TRIVIAL]),
        case("descending letters", &p, "mlkjihgfedcba", &[TRIVIAL]),
        case(
            "case-insensitive: ascending",
            &p,
            "AbCdEfGhIjKlMn",
            &[TRIVIAL],
        ),
        case(
            "case-insensitive: descending",
            &p,
            "ZYXWVUTSRQPONM",
            &[TRIVIAL],
        ),
        case("ascending punctuation", &p, "!\"#$%&'()*+,-", &[TRIVIAL]),
        case(
            "fullwidth letters repeated",
            &p,
            "\u{ff41}".repeat(12),
            &[TRIVIAL],
        ),
        case(
            "too long and trivial",
            &p,
            "a".repeat(300),
            &[too_long(256), TRIVIAL],
        ),
        // Near misses and patterns outside the rule.
        case("one character differs at the end", &p, "abcabcabcabd", &[]),
        case("a run with a break", &p, "abcdefghijkm", &[]),
        case("repeated but for the last", &p, "aaaaaaaaaaab", &[]),
        case("a unit of four is not covered", &p, "abcdabcdabcd", &[]),
        case("a keyboard walk is not covered", &p, "qwertyuiopas", &[]),
        case(
            "a mixed ascending and descending run",
            &p,
            "abcdefgfedcba",
            &[],
        ),
        case("natural words", &p, "correcthorsebatterystaple", &[]),
    ]);
}

#[test]
fn control_character_vectors() {
    let p = PasswordPolicy::Standard;
    run(vec![
        case("newline", &p, "line one\nline two", &[CONTROL]),
        case("carriage return", &p, "carriage\rreturn pass", &[CONTROL]),
        case("tab", &p, "tab\tseparated pass", &[CONTROL]),
        case("NUL", &p, "nul\0byte in the middle", &[CONTROL]),
        case("DEL", &p, "delete\u{7f}char in password", &[CONTROL]),
        case(
            "a C1 control character",
            &p,
            "c1 control\u{85} char pw",
            &[CONTROL],
        ),
        case("escape", &p, "escape\u{1b}sequence pw", &[CONTROL]),
        case(
            "plain spaces are not control characters",
            &p,
            "just some spaces here",
            &[],
        ),
        case(
            "no-break space is not a control character",
            &p,
            "no\u{a0}break\u{a0}spaces",
            &[],
        ),
        case(
            "ideographic space is a space",
            &p,
            "correct\u{3000}horse\u{3000}staple",
            &[],
        ),
        case(
            "in a PIN",
            &PasswordPolicy::Pin,
            "12\t34",
            &[CONTROL, DIGITS_ONLY],
        ),
        case(
            "in a Custom password",
            &custom(8, 64, None),
            "line\none pass",
            &[CONTROL],
        ),
    ]);
}

#[test]
fn normalization_and_length_vectors() {
    let p = PasswordPolicy::Standard;
    let eleven_ideographs = ideographs(11);
    let twelve_ideographs = ideographs(12);
    assert!(twelve_ideographs.len() >= 36);
    run(vec![
        case(
            "composed accents count once",
            &p,
            "cr\u{e8}me-br\u{fb}l\u{e9}e",
            &[],
        ),
        case(
            "decomposed accents count once",
            &p,
            "cre\u{300}me-bru\u{302}le\u{301}e",
            &[],
        ),
        case(
            "composed, one character short",
            &p,
            "cr\u{e8}me-br\u{fb}l\u{e9}",
            &[too_short(12)],
        ),
        case(
            "decomposed, one character short",
            &p,
            "cre\u{300}me-bru\u{302}le\u{301}",
            &[too_short(12)],
        ),
        case(
            "characters, not bytes: 12 ideographs",
            &p,
            twelve_ideographs,
            &[],
        ),
        case(
            "characters, not bytes: 11 ideographs",
            &p,
            eleven_ideographs,
            &[too_short(12)],
        ),
        case(
            "characters, not bytes: 256 ideographs",
            &p,
            ideographs(256),
            &[],
        ),
        case(
            "characters, not bytes: 257 ideographs",
            &p,
            ideographs(257),
            &[too_long(256)],
        ),
        case(
            "a ligature expands to two characters",
            &p,
            "\u{fb01}".repeat(6),
            &[TRIVIAL],
        ),
        case(
            "fullwidth letters are ASCII letters",
            &p,
            "\u{ff43}\u{ff4f}\u{ff52}\u{ff52}\u{ff45}\u{ff43}\u{ff54}-horse-staple",
            &[],
        ),
        case(
            "the context is matched after normalization",
            &p,
            "\u{ff52}\u{ff4a}\u{ff41}\u{ff4d}\u{ff45}\u{ff53}-is-my-login",
            &[context(ContextKind::UserName)],
        ),
        case(
            "a decomposed password matches a composed user name",
            &p,
            "my-zoe\u{308}-pw-123",
            &[context(ContextKind::UserName)],
        )
        .in_context(PasswordContext {
            user_name: "Zo\u{eb}",
            display_name: None,
            host_name: None,
        }),
        case(
            "a composed password matches a decomposed user name",
            &p,
            "my-zo\u{eb}-pw-123",
            &[context(ContextKind::UserName)],
        )
        .in_context(PasswordContext {
            user_name: "Zoe\u{308}",
            display_name: None,
            host_name: None,
        }),
    ]);
}

#[test]
fn context_vectors() {
    let p = PasswordPolicy::Standard;
    let user = || context(ContextKind::UserName);
    let display = || context(ContextKind::DisplayName);
    let host = || context(ContextKind::HostName);
    let product = || context(ContextKind::Product);
    run(vec![
        case("the user name", &p, "xxrjamesxx-pw1", &[user()]),
        case("the user name, any case", &p, "XXRJAMESXX-PW1", &[user()]),
        case(
            "a part of the display name",
            &p,
            "my-ROWAN-is-here",
            &[display()],
        ),
        case(
            "the other part of the display name",
            &p,
            "I like jameson whiskey",
            &[display()],
        ),
        case(
            "the whole display name",
            &p,
            "rowan jameson loves tea",
            &[display()],
        ),
        case(
            "the first label of the host name",
            &p,
            "go-to-gateway01-now",
            &[host()],
        ),
        case(
            "the whole host name",
            &p,
            "gateway01.lab.test-pass",
            &[host()],
        ),
        case(
            "the host name in capitals",
            &p,
            "GATEWAY01.LAB.TEST-pass",
            &[host()],
        ),
        case("the product name", &p, "Tenko-is-my-product", &[product()]),
        case(
            "the product name in capitals",
            &p,
            "TENKO!!!!!!!!",
            &[product()],
        ),
        case(
            "the product name inside a word",
            &p,
            "xtenkox-pass-1",
            &[product()],
        ),
        case(
            "every kind, in order",
            &p,
            "rjames-rowan-gateway01-tenko",
            &[user(), display(), host(), product()],
        ),
        case(
            "every kind, in another order in the password",
            &p,
            "tenko+gateway01+rowan+rjames",
            &[user(), display(), host(), product()],
        ),
        case("two kinds", &p, "gateway01-and-rjames-1", &[user(), host()]),
        case(
            "a word that is in none of them",
            &p,
            "rowa-jame-gatew-tenk",
            &[],
        ),
    ]);
}

#[test]
fn context_word_length_vectors() {
    let p = PasswordPolicy::Standard;
    let user = || context(ContextKind::UserName);
    let display = || context(ContextKind::DisplayName);
    let with = |user_name, display_name, host_name| PasswordContext {
        user_name,
        display_name,
        host_name,
    };
    run(vec![
        case_in(
            "a user name below three characters is ignored",
            &p,
            "xxabxx-secret",
            with("ab", None, None),
            &[],
        ),
        case_in(
            "a user name of three characters counts",
            &p,
            "xxabcxx-secret",
            with("abc", None, None),
            &[user()],
        ),
        case_in(
            "an empty user name matches nothing",
            &p,
            "anything-goes-here",
            with("", None, None),
            &[],
        ),
        case_in(
            "display name parts below four characters are ignored",
            &p,
            "xx-al-bo-yy-zz",
            with("nobody", Some("Al Bo"), None),
            &[],
        ),
        case_in(
            "a short display name still counts as a whole",
            &p,
            "xx al bo yy zz",
            with("nobody", Some("Al Bo"), None),
            &[display()],
        ),
        case_in(
            "a display name of three characters is ignored",
            &p,
            "bobsled-racing",
            with("nobody", Some("Bob"), None),
            &[],
        ),
        case_in(
            "an empty display name matches nothing",
            &p,
            "anything-goes-here",
            with("nobody", Some(""), None),
            &[],
        ),
    ]);
}

#[test]
fn context_host_word_vectors() {
    let p = PasswordPolicy::Standard;
    let host = || context(ContextKind::HostName);
    let product = || context(ContextKind::Product);
    let with = |user_name, display_name, host_name| PasswordContext {
        user_name,
        display_name,
        host_name,
    };
    run(vec![
        case_in(
            "a host name without dots",
            &p,
            "my-ns1-box-pw",
            with("nobody", None, Some("ns1")),
            &[host()],
        ),
        case_in(
            "a host name below three characters is ignored",
            &p,
            "my-ns-box-pw1",
            with("nobody", None, Some("ns")),
            &[],
        ),
        case_in(
            "a first label below three characters is ignored",
            &p,
            "my-ns-box-pw1",
            with("nobody", None, Some("ns.lab.test")),
            &[],
        ),
        case_in(
            "a host name with a trailing dot",
            &p,
            "go-to-gateway01-now",
            with("nobody", None, Some("gateway01.lab.test.")),
            &[host()],
        ),
        case_in(
            "nothing is known about the account",
            &p,
            "rjames-rowan-gateway01",
            BARE,
            &[],
        ),
        case_in(
            "the product word needs no context",
            &p,
            "my-tenko-install",
            BARE,
            &[product()],
        ),
    ]);
}

#[test]
fn the_breach_check_is_not_part_of_the_policy() {
    let p = PasswordPolicy::Standard;
    for password in ["password1234", "Passw0rd!Passw0rd!", "letmein-letmein"] {
        assert!(
            !p.check(password, &CONTEXT)
                .iter()
                .any(|violation| matches!(violation, PolicyViolation::Breached { .. })),
            "{password}"
        );
    }
}

#[test]
fn every_violation_has_a_stable_code() {
    let violations = PasswordPolicy::Pin.check("ab\n", &CONTEXT);
    let codes: Vec<_> = violations.iter().map(PolicyViolation::code).collect();
    assert_eq!(
        codes,
        [
            "auth.password.invalid_characters",
            "auth.password.pin_digits_only",
            "auth.password.too_short",
        ]
    );
    assert_eq!(violations[2].params()["min"], "4");
}

#[test]
fn validate_vectors() {
    let invalid = |reason: &'static str| Err(AuthError::invalid("password_policy", reason));
    let not_valid = "pattern is not a valid regular expression";
    let rows: Vec<(PasswordPolicy, Result<(), AuthError>)> = vec![
        (PasswordPolicy::Pin, Ok(())),
        (PasswordPolicy::Standard, Ok(())),
        (PasswordPolicy::Hardened, Ok(())),
        (PasswordPolicy::default(), Ok(())),
        (custom(4, 64, None), Ok(())),
        (custom(64, 64, None), Ok(())),
        (custom(4, 1024, None), Ok(())),
        (custom(1024, 1024, None), Ok(())),
        (custom(500, 600, Some("[a-z]+")), Ok(())),
        (custom(12, 256, Some(r"[[:alpha:]]+\d+")), Ok(())),
        (
            custom(3, 64, None),
            invalid("min_length must be at least 4"),
        ),
        (
            custom(0, 64, None),
            invalid("min_length must be at least 4"),
        ),
        (
            custom(4, 63, None),
            invalid("max_length must be at least 64"),
        ),
        (
            custom(4, 0, None),
            invalid("max_length must be at least 64"),
        ),
        (
            custom(4, 1025, None),
            invalid("max_length must not exceed 1024"),
        ),
        (
            custom(65, 64, None),
            invalid("min_length must not exceed max_length"),
        ),
        (
            custom(1000, 999, None),
            invalid("min_length must not exceed max_length"),
        ),
        (custom(8, 64, Some("(")), invalid(not_valid)),
        (custom(8, 64, Some("[a-")), invalid(not_valid)),
        (custom(8, 64, Some("[z-a]")), invalid(not_valid)),
        (custom(8, 64, Some("a{2,1}")), invalid(not_valid)),
        (custom(8, 64, Some("*")), invalid(not_valid)),
        (custom(8, 64, Some("a)(b")), invalid(not_valid)),
        (custom(8, 64, Some(r"\p{NoSuchClass}+")), invalid(not_valid)),
        (
            custom(8, 64, Some("")),
            invalid("pattern must not be empty"),
        ),
        (
            custom(8, 64, Some("((a{1000}){1000}){1000}")),
            invalid("pattern is too complex"),
        ),
    ];
    for (policy, expected) in rows {
        assert_eq!(policy.validate(), expected, "{policy:?}");
    }
}

#[test]
fn limits_of_the_presets() {
    let rows = [
        (PasswordPolicy::Pin, 4, 64),
        (PasswordPolicy::Standard, 12, 256),
        (PasswordPolicy::Hardened, 16, 256),
        (custom(9, 99, None), 9, 99),
    ];
    for (policy, min, max) in rows {
        assert_eq!((policy.min_length(), policy.max_length()), (min, max));
    }
    assert!(PasswordPolicy::Pin.is_pin());
    assert!(!PasswordPolicy::Hardened.is_pin());
}

#[test]
fn json_round_trip_of_the_setting() {
    for (json, policy) in [
        (r#"{"preset":"pin"}"#, PasswordPolicy::Pin),
        (r#"{"preset":"standard"}"#, PasswordPolicy::Standard),
        (r#"{"preset":"hardened"}"#, PasswordPolicy::Hardened),
        (
            r#"{"preset":"custom","min_length":10,"max_length":128,"pattern":null}"#,
            custom(10, 128, None),
        ),
        (
            r#"{"preset":"custom","min_length":10,"max_length":256,"pattern":"[a-z]+"}"#,
            custom(10, 256, Some("[a-z]+")),
        ),
    ] {
        let parsed: PasswordPolicy = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed, policy, "{json}");
        assert_eq!(serde_json::to_string(&policy).expect("serialize"), json);
    }
    let minimal: PasswordPolicy =
        serde_json::from_str(r#"{"preset":"custom","min_length":14}"#).expect("parse");
    assert_eq!(minimal, custom(14, 256, None));
}

#[test]
fn the_schema_names_the_tag_and_the_presets() {
    let schema = <PasswordPolicy as utoipa::PartialSchema>::schema();
    let json = serde_json::to_string(&schema).expect("serialize the schema");
    for expected in [
        "preset",
        "pin",
        "standard",
        "hardened",
        "custom",
        "min_length",
    ] {
        assert!(json.contains(expected), "{expected} is missing from {json}");
    }
}

#[test]
fn normalization_is_idempotent_and_nfkc() {
    for (input, expected) in [
        ("plain", "plain"),
        ("", ""),
        ("e\u{301}", "\u{e9}"),
        ("\u{ff21}\u{ff22}\u{ff23}", "ABC"),
        ("\u{fb03}", "ffi"),
        ("a\u{3000}b", "a b"),
    ] {
        let once = normalize(input);
        assert_eq!(once.as_str(), expected);
        assert_eq!(normalize(&once).as_str(), expected);
    }
}
