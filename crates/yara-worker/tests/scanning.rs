//! Integration tests: black-box exercise of the worker's pure YARA logic
//! (compile → scan, multi-rule, the hostile-input contract) the same way the SQL
//! E2E suite drives it, but without the Arrow/RPC layer.
//!
//! The pure logic lives in a private module of the binary crate, so we include it
//! by path.

#[path = "../src/scanning.rs"]
#[allow(dead_code)]
mod scanning;

use scanning::{
    compile_and_scan_rules, compile_and_scan_strings, compile_rules, rules_compile, scan_rules,
};

const DEMO: &str = r#"rule demo { strings: $a = "malware" condition: $a }"#;

#[test]
fn demo_rule_matches_and_reports_name() {
    let m = compile_and_scan_rules(DEMO, b"contains malware here").unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].rule, "demo");
}

#[test]
fn string_match_offset_is_correct() {
    let hits = compile_and_scan_strings(DEMO, b"0123malware").unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].offset, 4);
    assert_eq!(hits[0].matched, "malware");
}

#[test]
fn non_matching_data_yields_nothing() {
    assert!(compile_and_scan_rules(DEMO, b"all clean")
        .unwrap()
        .is_empty());
    assert!(compile_and_scan_strings(DEMO, b"all clean")
        .unwrap()
        .is_empty());
}

#[test]
fn multi_rule_set() {
    let src = r#"
        rule a : t1 { strings: $x = "aaa" condition: $x }
        rule b : t2 { strings: $y = "bbb" condition: $y }
    "#;
    let mut m = compile_and_scan_rules(src, b"aaa and bbb").unwrap();
    m.sort_by(|x, y| x.rule.cmp(&y.rule));
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].tags, vec!["t1".to_string()]);
    assert_eq!(m[1].tags, vec!["t2".to_string()]);
}

#[test]
fn check_true_and_false() {
    assert!(rules_compile(DEMO));
    assert!(!rules_compile("rule broken { condition: }"));
}

#[test]
fn invalid_rule_source_errors() {
    assert!(compile_rules("rule broken { condition: }").is_err());
    assert!(compile_rules("not yara at all").is_err());
}

#[test]
fn garbage_empty_binary_blobs_do_not_panic() {
    let rules = compile_rules(DEMO).unwrap();
    assert!(scan_rules(&rules, b"").is_empty());
    assert!(scan_rules(&rules, b"\x00\xff\xfe\x7f garbage").is_empty());
    let binary: Vec<u8> = (0u16..1024).map(|x| (x & 0xff) as u8).collect();
    assert!(scan_rules(&rules, &binary).is_empty());
}

#[test]
fn bad_blob_beside_good_one_stays_alive() {
    let rules = compile_rules(DEMO).unwrap();
    let hostile: Vec<u8> = (0u32..200_000)
        .map(|x| (x.wrapping_mul(2654435761) % 256) as u8)
        .collect();
    assert!(scan_rules(&rules, &hostile).is_empty());
    // The good blob still matches afterwards — the worker survived the hostile one.
    let m = scan_rules(&rules, b"malware payload");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].rule, "demo");
}
