//! Issue #688. The reader the workflow sweeps parse YAML with.
//!
//! `serde_yaml_ng` was replaced because `RUSTSEC-2024-0449` marks the
//! `unsafe-libyaml` under it unmaintained. Swapping the parser under a hundred
//! assertions is only safe if the new reading answers the old questions the
//! same way, so this file pins the answers rather than trusting that it does.
//!
//! While both crates were declared, the two readers were compared directly:
//! **93 comparisons over 17 documents and 6 keys, including five-level paths,
//! with zero divergence** on `missing_or_null`, `as_str`, sequence length and
//! `as_bool`. That throwaway comparison died with the old crate; what stays
//! below is the answer it produced, written as a literal. A reader swapped
//! again has to reproduce these, or say in a diff why it does not.
//!
//! The 93 is the measured count, not a target: the loop compared every key
//! against every document, so most pairs are an absent key, which is the case
//! the old reader answered `Null` for and the new one answers `None`.

mod common;

use common::{dig, missing_or_null, seq, string_keys, text, yaml_doc};
use saphyr::{LoadableYamlNode, YamlOwned};

fn doc(src: &str) -> YamlOwned {
  yaml_doc("<test>", src)
}

/// An absent key and a key whose value is YAML null are the same answer.
///
/// Not an accident of the new reader: `serde_yaml_ng` indexed a mapping and
/// answered `is_null() == true` for both, and every `must carry no X:`
/// assertion in these sweeps was written against that. `missing_or_null` keeps
/// the two together on purpose. Telling them apart is a change to make with a
/// test of its own, which is why this one exists to notice it.
#[test]
fn an_absent_key_and_an_explicit_null_read_alike() {
  for src in ["other: 1", "if: ~", "if: null", "if:"] {
    let d = doc(src);
    assert!(
      missing_or_null(dig(&d, &["if"])),
      "`{src}` must read as missing-or-null for the `if` key"
    );
  }
}

/// A false boolean is not a null, which is the defect fixed at `6bb82758`.
///
/// `if: false` switches a job off and is the canonical way to do it. A reader
/// that answered "null" for it would take the "no `if:` at all" arm of
/// `assert_job_is_blocking` and pass the one case it exists to catch.
#[test]
fn a_false_boolean_is_not_read_as_absent() {
  let d = doc("if: false");
  assert!(
    !missing_or_null(dig(&d, &["if"])),
    "`if: false` must not read as missing-or-null: it is the canonical off switch"
  );
  assert_eq!(dig(&d, &["if"]).and_then(|v| v.as_bool()), Some(false));
  assert_eq!(
    text(dig(&d, &["if"])),
    None,
    "a boolean must read as no string, so a sweep comparing `as_str()` cannot see it"
  );
}

/// Walking past an absent level answers nothing instead of panicking.
///
/// This is the whole reason `dig` exists. `saphyr` panics when `[]` meets a
/// key that is not there or a scalar, where `serde_yaml_ng` answered `Null`
/// and let the next index run. Three levels, because the shortest real path
/// in these sweeps is `job["defaults"]["run"]["shell"]`.
#[test]
fn digging_through_an_absent_level_answers_none() {
  let d = doc("jobs:\n  build:\n    id: 1\n");
  assert!(dig(&d, &["jobs", "build"]).is_some());
  assert!(dig(&d, &["jobs", "nope"]).is_none());
  assert!(dig(&d, &["nope", "deeper", "deepest"]).is_none());
  assert!(
    dig(&d, &["jobs", "build", "id", "x"]).is_none(),
    "indexing through a scalar must answer none, not panic"
  );
}

/// A sequence read off an absent path is empty, not a panic.
#[test]
fn a_sequence_at_an_absent_path_is_empty() {
  let d = doc("strategy:\n  matrix:\n    os: [ubuntu-latest, macos-latest]\n");
  assert_eq!(seq(dig(&d, &["strategy", "matrix", "os"])).len(), 2);
  assert!(seq(dig(&d, &["strategy", "matrix", "exclude"])).is_empty());
  assert!(seq(dig(&d, &["nope"])).is_empty());
  assert!(
    seq(dig(&d, &["strategy", "matrix"])).is_empty(),
    "a mapping is not a sequence, and reading one as a sequence must be empty rather than a panic"
  );
}

/// The keys of a mapping come back in document order, not sorted.
///
/// Measured, because the obvious replacement fails it: deserialising the YAML
/// into `serde_json::Value` sorts the keys, and `["build", "release"]` happens
/// to be alphabetical, so `string_keys_returns_every_key_in_order` would have
/// kept passing while the order it names was gone. The sample here is
/// deliberately not alphabetical.
#[test]
fn mapping_keys_keep_document_order() {
  let d = doc("jobs:\n  zebra:\n    id: 1\n  alpha:\n    id: 2\n  middle:\n    id: 3\n");
  let jobs = dig(&d, &["jobs"]).expect("jobs");
  assert_eq!(
    string_keys(jobs.as_mapping().expect("a mapping"), "jobs"),
    ["zebra", "alpha", "middle"],
    "the reader must preserve document order: a sweep that reports the first offending job \
     by position reports the wrong one if the keys are sorted"
  );
}

/// A key the reader does not read as a string is still visible as such.
///
/// `string_keys` panics on it rather than skipping it (#673), and that panic is
/// only reachable if the reader can represent the key at all. The other
/// candidate reader for this migration could not: going through
/// `serde_json::Value` turns `true:` into the string `"true"`, which silently
/// makes `string_keys` unable to fire and turns a live guard into a vacuous
/// one.
#[test]
#[should_panic(expected = "every key must be a string")]
fn a_non_string_key_is_still_a_non_string_key() {
  let d = doc("jobs:\n  true:\n    id: 1\n");
  let jobs = dig(&d, &["jobs"]).expect("jobs");
  string_keys(jobs.as_mapping().expect("a mapping"), "jobs");
}

/// The three `permissions:` shapes the #681 guards compare stay distinct.
///
/// `write-all` is a string, `{}` is an empty mapping and an absent key is
/// nothing. A reader that collapsed any two of them would pass one of the
/// mutations those guards were written against.
#[test]
fn the_three_permission_shapes_stay_distinct() {
  let wide = doc("permissions: write-all");
  let empty = doc("permissions: {}");
  let absent = doc("other: 1");

  assert_eq!(text(dig(&wide, &["permissions"])), Some("write-all"));
  assert_eq!(text(dig(&empty, &["permissions"])), None);
  assert_eq!(text(dig(&absent, &["permissions"])), None);

  assert!(
    dig(&empty, &["permissions"]).is_some(),
    "`permissions: {{}}` is a grant of nothing and must be visible as present"
  );
  assert!(
    dig(&absent, &["permissions"]).is_none(),
    "an absent `permissions:` must be visible as absent, which is what tells it from `{{}}`"
  );
  assert_ne!(
    dig(&empty, &["permissions"]),
    dig(&wide, &["permissions"]),
    "comparing by value is what tells `{{}}` from `write-all`; `as_str()` reads None for the \
     first and Some for the second, which is the half of the trap #669 names"
  );
}

/// Two parses of the same text compare equal, which is what the by-value
/// `permissions:` assertions rest on.
#[test]
fn equal_documents_compare_equal() {
  assert_eq!(doc("contents: read"), doc("contents: read"));
  assert_ne!(doc("contents: read"), doc("contents: write"));
}

/// A multi-document file is refused rather than silently read as its first
/// document.
///
/// No workflow in `.github/workflows` is multi-document, and one appearing
/// would mean the file means something other than what every sweep here reads.
#[test]
fn the_workflows_are_single_document() {
  for path in std::fs::read_dir(".github/workflows").expect("the workflows directory must exist") {
    let path = path.expect("a readable entry").path();
    let name = path.display().to_string();
    if !name.ends_with(".yml") && !name.ends_with(".yaml") {
      continue;
    }
    let text = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| panic!("{name} must be readable: {e}"))
      .replace("\r\n", "\n");
    let docs = YamlOwned::load_from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(
      docs.len(),
      1,
      "{name} must hold exactly one YAML document: every sweep reads only the first, so a \
       second one would be unaudited"
    );
  }
}
