//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table.
//!
//! Each function/table surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)        — human-friendly display name
//! - `vgi.doc_llm` (VGI112)      — narrative Markdown prose aimed at LLMs/agents
//! - `vgi.doc_md` (VGI113)       — narrative Markdown description for human docs
//! - `vgi.keywords` (VGI126/VGI138) — search terms/synonyms, as a JSON array of
//!   strings (`["a","b"]`), NOT a comma-separated string
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted: source-link
//! provenance lives once on the catalog object (VGI004); repeating it on every
//! function/schema is flagged as redundant by VGI139.

/// Encode a comma-separated keyword list as a JSON array of strings, e.g.
/// `"a, b"` → `["a","b"]`. Each keyword is JSON-string-escaped so a stray quote
/// or backslash can never produce invalid JSON. Required by VGI138, which wants
/// `vgi.keywords` to be a JSON array rather than a bare comma-separated string.
pub fn keywords_json(comma_separated: &str) -> String {
    let mut out = String::from("[");
    let mut first = true;
    for kw in comma_separated.split(',') {
        let kw = kw.trim();
        if kw.is_empty() {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        for ch in kw.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                _ => out.push(ch),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

/// Build the standard per-object discovery/description tags.
///
/// `keywords` is given as a comma-separated string for ergonomics and is encoded
/// to the JSON-array form VGI138 requires. `category` names one of the schema's
/// declared `vgi.categories` (VGI413), so the object slots into the worker's
/// navigation/listing sections. No per-object `vgi.source_url` is emitted (see
/// module docs / VGI139).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    category: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
        ("vgi.category".to_string(), category.to_string()),
    ]
}
