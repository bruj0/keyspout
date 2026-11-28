//! Provenance and reconciliation: what an import wrote, and what the next one
//! decides about it.
//!
//! # Why the assertions here are about the store, not the report
//!
//! Misfit G's dangerous half is that a second import of a changed file **deletes
//! a record that still matters**, and reports nothing. A test that only reads the
//! report cannot catch it: the report is what says the deletion happened, so a
//! report that omits the deletion is exactly the defect. So every test that
//! asserts "nothing was deleted" asks the **store** whether the record is still
//! there, and every test that asserts "one new version" counts versions in the
//! store.
//!
//! Misfit I is the other half: the copy is invisible. The assertion is that after
//! an import, a reader who never saw the command can learn where a value came
//! from — from the ledger, which is the one place the plan put it (KDD-1).
//!
//! # What this file can and cannot test
//!
//! There is no deployment fixture here. `admin init` writes a sealed vault and
//! binds a UNIX account; that is privileged setup and it belongs to WP07's
//! end-to-end run. What lives here is the ledger, the reconciliation and the
//! report — the parts whose correctness does not depend on a deployment existing,
//! because they take a store, a source identifier and a map of pairs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ksp::import::provenance::{
    Disposition, ImportLedgerEntry, reconcile, record_import, source_id_for_file, value_digest,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A temporary home, with a store under it.
struct Home {
    root: PathBuf,
}

impl Home {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("ksp-import-prov-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn layout(&self) -> ksp::config::Layout {
        ksp::config::Layout::new(self.root.clone())
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// One entry as the reconciler's second input: what the *store* currently holds.
fn present(versions: &[(&str, u32)]) -> BTreeMap<String, u32> {
    versions
        .iter()
        .map(|(key, version)| ((*key).to_string(), *version))
        .collect()
}

fn pairs(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

/// The ledger row this import of `key` wrote for `value`.
fn entry_for(source: &str, key: &str, value: &str, version: u32) -> ImportLedgerEntry {
    ImportLedgerEntry {
        source_id: source.to_string(),
        key: key.to_string(),
        secret_id: format!("s-{key}"),
        version,
        value_digest: value_digest(value.as_bytes()),
        imported_at: 1_760_000_000,
    }
}

/// A ledger row whose value the caller does not care about.
fn entry(source: &str, key: &str, version: u32) -> ImportLedgerEntry {
    entry_for(source, key, "", version)
}

// ---------------------------------------------------------------------------
// T002 — a source identifier names one file however it was written
// ---------------------------------------------------------------------------

#[test]
fn the_same_file_named_two_ways_is_one_source() {
    // Without canonicalisation every import looks like a first import, so the
    // `absent` computation never fires and misfit G is unreachable.
    let home = Home::new("canonical");
    let file = home.root.join("team1.env");
    std::fs::write(&file, "A=1\n").unwrap();

    let direct = source_id_for_file(&file).expect("an existing file has a source id");
    let indirect = source_id_for_file(&home.root.join("./team1.env"))
        .expect("a dotted path names the same file");
    let through_parent = source_id_for_file(
        &home
            .root
            .join("..")
            .join(home.root.file_name().expect("the temp home has a name"))
            .join("team1.env"),
    )
    .expect("a path through `..` names the same file");

    assert_eq!(direct, indirect, "`./` must not mint a second source");
    assert_eq!(
        direct, through_parent,
        "`..` must not mint a second source, or re-importing after a `cd` would \
         report every key as new"
    );
}

#[test]
fn a_file_that_does_not_exist_has_no_source_id() {
    // A source id that named a path nothing can read would let a typo create a
    // ledger lineage that reconciles against nothing forever.
    let home = Home::new("missing");
    let error = source_id_for_file(&home.root.join("absent.env"))
        .expect_err("a missing file must not produce a source id");
    assert!(
        !error.to_string().trim().is_empty(),
        "the refusal must say why"
    );
}

// ---------------------------------------------------------------------------
// T001 — the ledger file, and its mode
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_lives_in_the_home_and_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let home = Home::new("mode");
    let layout = home.layout();
    record_import(&layout, &[entry("file:/tmp/team1.env", "A", 1)])
        .expect("the ledger is created on first append");

    let path = layout.imports_ledger();
    assert!(path.is_file(), "the ledger must exist after an append");

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "a ledger naming which keys came from which file is owner-only; got {mode:o}"
    );
}

#[test]
fn the_ledger_appends_rather_than_replacing() {
    // The precedent is `issuance.jsonl`: append-only, because the question the
    // ledger answers is "what did the last import of this source write", and a
    // replacement answers "what did this one write" — not the same question.
    let home = Home::new("append");
    let layout = home.layout();

    record_import(&layout, &[entry("file:/tmp/team1.env", "A", 1)]).unwrap();
    record_import(&layout, &[entry("file:/tmp/team1.env", "A", 2)]).unwrap();

    let text = std::fs::read_to_string(layout.imports_ledger()).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 2, "both appends must survive; got {lines:?}");
}

#[test]
fn a_ledger_row_carries_the_five_fields_the_plan_names() {
    let home = Home::new("row");
    let layout = home.layout();
    record_import(&layout, &[entry("file:/tmp/team1.env", "A", 3)]).unwrap();

    let text = std::fs::read_to_string(layout.imports_ledger()).unwrap();
    let row: serde_json::Value =
        serde_json::from_str(text.lines().next().expect("one row")).expect("a row is JSON");

    for field in ["source_id", "key", "secret_id", "version", "imported_at"] {
        assert!(
            row.get(field).is_some(),
            "a ledger row must carry `{field}`; got {row}"
        );
    }
    assert_eq!(row["version"], 3);
}

// ---------------------------------------------------------------------------
// T004 — reconciliation against the last import of the same source
// ---------------------------------------------------------------------------

#[test]
fn a_first_import_makes_every_key_new() {
    let decided = reconcile(
        &pairs(&[("A", "1"), ("B", "2")]),
        &present(&[]),
        &ksp::import::provenance::ImportLedger::default(),
    );

    assert_eq!(decided.len(), 2);
    for row in &decided {
        assert_eq!(
            row.disposition,
            Disposition::New,
            "{} is in no earlier import, so it is new",
            row.key
        );
    }
}

#[test]
fn an_unchanged_value_is_unchanged_and_rewrites_nothing() {
    // Misfit G's stale-overwrite half: a re-import of an identical file must not
    // bump every version. A version bump is not cosmetic — it is the unit a lease
    // deletes and a delivery binds.
    let previous = ksp::import::provenance::ImportLedger::from_entries(&[entry_for(
        "file:/tmp/team1.env",
        "A",
        "1",
        1,
    )]);
    let decided = reconcile(&pairs(&[("A", "1")]), &present(&[("A", 1)]), &previous);

    assert_eq!(decided.len(), 1);
    assert_eq!(
        decided[0].disposition,
        Disposition::Unchanged,
        "the value is byte-identical, so nothing should be written"
    );
    assert!(
        decided[0].writes.is_none(),
        "an unchanged key must not produce a write"
    );
}

#[test]
fn a_changed_value_is_changed_and_writes_one_new_version() {
    let previous = ksp::import::provenance::ImportLedger::from_entries(&[entry_for(
        "file:/tmp/team1.env",
        "A",
        "1",
        1,
    )]);
    let decided = reconcile(&pairs(&[("A", "2")]), &present(&[("A", 1)]), &previous);

    assert_eq!(decided.len(), 1);
    assert_eq!(decided[0].disposition, Disposition::Changed);
    assert_eq!(
        decided[0].writes.as_deref(),
        Some("2"),
        "a changed key writes exactly one new value"
    );
}

// ---------------------------------------------------------------------------
// T005 / acceptance criterion 1 — the two-word `absent`
// ---------------------------------------------------------------------------

#[test]
fn a_key_the_file_dropped_is_absent_from_the_source() {
    let previous = ksp::import::provenance::ImportLedger::from_entries(&[
        entry_for("file:/tmp/team1.env", "A", "1", 1),
        entry_for("file:/tmp/team1.env", "B", "1", 1),
    ]);
    // The store still holds B; only the file stopped naming it.
    let decided = reconcile(
        &pairs(&[("A", "1")]),
        &present(&[("A", 1), ("B", 1)]),
        &previous,
    );

    let b = decided
        .iter()
        .find(|row| row.key == "B")
        .expect("B is reconciled");
    assert_eq!(
        b.disposition,
        Disposition::AbsentNotInSource,
        "B is in the ledger and still in the store, so the file dropped it"
    );
    assert!(
        b.writes.is_none(),
        "an absent key must never produce a write, and never a delete (misfit G)"
    );
}

#[test]
fn a_record_the_store_lost_is_absent_removed() {
    // The other word, and the reason the two words exist: the repairs differ.
    // "not in source" says the file changed; "removed" says a sweep took a record
    // the source still names, and re-importing restores it.
    let previous = ksp::import::provenance::ImportLedger::from_entries(&[
        entry_for("file:/tmp/team1.env", "A", "1", 1),
        entry_for("file:/tmp/team1.env", "B", "1", 1),
    ]);
    // B is still named by the file, but the store no longer holds it.
    let decided = reconcile(
        &pairs(&[("A", "1"), ("B", "2")]),
        &present(&[("A", 1)]),
        &previous,
    );

    let b = decided
        .iter()
        .find(|row| row.key == "B")
        .expect("B is reconciled");
    assert_eq!(
        b.disposition,
        Disposition::AbsentRemoved,
        "the source still names B and the store lost it, so a sweep removed it; \
         reporting `not in source` would send the operator to edit a file that is \
         already correct"
    );
}

#[test]
fn both_absent_words_are_distinguishable_in_one_report() {
    // A single report can carry both, and a reader must be able to tell them
    // apart. One word for both is the defect the two-word distinction exists to
    // prevent, so the test asserts the rendering differs.
    let previous = ksp::import::provenance::ImportLedger::from_entries(&[
        entry_for("file:/tmp/team1.env", "DROPPED", "1", 1),
        entry_for("file:/tmp/team1.env", "SWEPT", "1", 1),
        entry_for("file:/tmp/team1.env", "KEPT", "1", 1),
    ]);
    let decided = reconcile(
        &pairs(&[("KEPT", "1"), ("SWEPT", "1")]),
        &present(&[("KEPT", 1), ("DROPPED", 1)]),
        &previous,
    );

    let dropped = decided.iter().find(|row| row.key == "DROPPED").unwrap();
    let swept = decided.iter().find(|row| row.key == "SWEPT").unwrap();

    assert_eq!(dropped.disposition, Disposition::AbsentNotInSource);
    assert_eq!(swept.disposition, Disposition::AbsentRemoved);
    assert_ne!(
        dropped.disposition.to_string(),
        swept.disposition.to_string(),
        "two situations with two different repairs must render differently"
    );
}

#[test]
fn a_re_import_deletes_nothing() {
    // Acceptance criterion 1's "still lists" half, asserted at the reconciler:
    // the decisions it returns can carry a value to write or nothing, and have no
    // way to express a delete. This test pins that shape, so a future arm that
    // carried a deletion would fail here rather than in a store.
    let previous = ksp::import::provenance::ImportLedger::from_entries(&[
        entry_for("file:/tmp/team1.env", "A", "1", 1),
        entry_for("file:/tmp/team1.env", "B", "1", 1),
    ]);
    let decided = reconcile(
        &pairs(&[("A", "2")]),
        &present(&[("A", 1), ("B", 1)]),
        &previous,
    );

    // `Unchanged` and `AbsentNotInSource` are the two arms that must leave the
    // store alone, and `B` is `AbsentNotInSource` here — the file dropped it and
    // the record is still there.
    //
    // This assertion originally said "writes exactly when new or changed", which
    // was wrong: it encoded the defect in `Disposition::writes` rather than the
    // property. `AbsentRemoved` must write, or a swept record never returns
    // however often the operator re-runs. That is not a deletion; it is the
    // opposite, and the old test was asserting the bug as a requirement.
    let dropped = decided
        .iter()
        .find(|row| row.key == "B")
        .expect("B is reconciled");
    assert_eq!(dropped.disposition, Disposition::AbsentNotInSource);
    assert!(
        dropped.writes.is_none(),
        "a key the file stopped naming must carry nothing to write, or a partial \
         copy would blank a record the operator still needs: {dropped:?}"
    );
}

#[test]
fn the_arms_that_carry_a_value_to_write_are_exactly_three() {
    // `Unchanged` and `AbsentNotInSource` carry nothing, and that is the whole
    // of "never delete": a caller that iterates decisions and writes what it
    // finds cannot blank a record the file merely stopped naming.
    //
    // The other three must carry their value. `AbsentRemoved` carrying nothing
    // was a real defect found in review: the store lost a record the source
    // still names, the report said so, and nothing put it back. The only way a
    // swept record returns is for this import to write it.
    for (disposition, expected) in [
        (Disposition::New, true),
        (Disposition::Changed, true),
        (Disposition::Unchanged, false),
        (Disposition::AbsentNotInSource, false),
        (Disposition::AbsentRemoved, true),
    ] {
        assert_eq!(
            disposition.writes(),
            expected,
            "{disposition} must write when {expected}"
        );
    }
}

#[test]
fn a_swept_record_is_restored_by_the_next_import() {
    // The defect this pins: `absent (removed)` reported the loss and wrote
    // nothing, so the record never came back and the report repeated itself on
    // every run. The arm's own documentation said "re-importing restores it",
    // which was false. A report that names a repair the command does not perform
    // sends the operator to re-run something that cannot help.
    let source = pairs(&[("SWEPT", "v1")]);
    // The store lost the record; the source still names it.
    let gone = present(&[]);
    let ledger = ksp::import::provenance::ImportLedger::from_entries(&[entry_for(
        "file:/tmp/a.env",
        "SWEPT",
        "v1",
        1,
    )]);

    let decisions = reconcile(&source, &gone, &ledger);
    assert_eq!(decisions[0].disposition, Disposition::AbsentRemoved);
    assert_eq!(
        decisions[0].writes.as_deref(),
        Some("v1"),
        "a swept record must be written again, or it is lost permanently"
    );
}

// ---------------------------------------------------------------------------
// The ledger as the reconciler's input
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_reads_back_the_last_import_of_one_source_only() {
    // A store typically holds several imports. Reconciling against another
    // source's rows would report its keys as absent from this file, which is
    // misfit G with the sources swapped.
    let home = Home::new("scoped");
    let layout = home.layout();

    record_import(&layout, &[entry_for("file:/tmp/team1.env", "A", "1", 1)]).unwrap();
    record_import(&layout, &[entry_for("file:/tmp/team2.env", "Z", "z", 1)]).unwrap();
    record_import(&layout, &[entry_for("file:/tmp/team1.env", "A", "2", 2)]).unwrap();

    let ledger = ksp::import::provenance::last_import(&layout, "file:/tmp/team1.env")
        .expect("the ledger is readable");

    assert_eq!(ledger.keys().collect::<Vec<_>>(), vec!["A"]);
    assert_eq!(
        ledger.version_of("A"),
        Some(2),
        "the last import of this source wrote version 2, and the first must not win"
    );
}

#[test]
fn a_source_that_was_never_imported_reads_as_empty_rather_than_failing() {
    // "never imported" and "readable but empty" are the same answer for the
    // reconciler, and conflating them with an error would make the first import
    // of every source fail.
    let home = Home::new("never");
    let layout = home.layout();
    let ledger = ksp::import::provenance::last_import(&layout, "file:/tmp/never.env")
        .expect("a missing source is an empty lineage");
    assert!(ledger.is_empty());
}

// ---------------------------------------------------------------------------
// T006 — the report, and the trap it must not repeat
// ---------------------------------------------------------------------------

#[test]
fn the_import_report_serialises_as_a_tagged_object_with_its_rows() {
    // `Report` is internally tagged, and serde cannot tag a newtype variant that
    // wraps a sequence: `to_value` returns `Err` and the emitter substitutes a
    // string, so every caller reads an empty listing. That shipped once. This
    // asserts the JSON a consumer actually parses, not a `Debug` rendering.
    use ksp::output::Report;

    let report = Report::Import {
        vault: "vault-bw-team1".to_string(),
        source_id: "file:/tmp/team1.env".to_string(),
        selector: "file:team1.env".to_string(),
        rows: vec![ksp::output::ImportRowView {
            key: "A".to_string(),
            disposition: "changed".to_string(),
            version: Some(2),
            source_id: "file:/tmp/team1.env".to_string(),
        }],
        records: 1,
    };

    let value = serde_json::to_value(&report).expect(
        "an internally tagged report must serialise; a failure here is the silent-empty bug",
    );
    assert_eq!(value["kind"], "import", "the tag must be present");
    assert_eq!(value["vault"], "vault-bw-team1");
    assert_eq!(value["records"], 1);
    let rows = value["rows"]
        .as_array()
        .expect("rows must be a JSON array, not a string");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["key"], "A");
    assert_eq!(rows[0]["disposition"], "changed");
    // NFR-005 names three fields per row, and the source identifier is the one a
    // consumer fans the array out on. Asserting only the key and the disposition
    // would let the identifier be dropped from the view without a test noticing,
    // which is the failure mode a field no test reads always has.
    assert_eq!(
        rows[0]["source_id"], "file:/tmp/team1.env",
        "each row must carry the source identifier beside its key and disposition"
    );
}

// ---------------------------------------------------------------------------
// Acceptance criterion 4 — the report names the vault
// ---------------------------------------------------------------------------

#[test]
fn the_report_names_the_vault_it_wrote_to() {
    // An operator with `vault-bw-team1` and `vault-bw-team2` on one host must be
    // able to see which one received the records without re-reading the command
    // they ran. A report that omits it leaves misfit J's first form undetectable
    // after the fact.
    use ksp::output::Report;

    let report = Report::Import {
        vault: "vault-bw-team1".to_string(),
        source_id: "file:/tmp/team1.env".to_string(),
        selector: "file:team1.env".to_string(),
        rows: vec![],
        records: 0,
    };

    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(
        value["vault"], "vault-bw-team1",
        "the report must name the destination vault"
    );
}

// ---------------------------------------------------------------------------
// Guard: the ledger path is part of the audited table
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_path_is_in_the_layout_table() {
    // T001's second half: a path that is not in the table is a path nobody
    // verifies. The test asks the table itself rather than the constant, so a
    // constant that no row names fails here.
    let home = Home::new("table");
    let layout = home.layout();

    let table = ksp::layout::table_at(layout.root(), None);
    let listed = table.iter().any(|row| row.path == layout.imports_ledger());

    assert!(
        listed,
        "`{}` must be a row in the layout table, or `ksp status` never measures it",
        layout.imports_ledger().display()
    );
}

#[test]
fn the_ledger_file_is_not_created_by_the_table() {
    // The table measures files; it does not create them. An empty ledger created
    // by a table would make "never imported" indistinguishable from "imported
    // nothing", which is the same defect the ledger exists to avoid.
    let home = Home::new("no-create");
    let layout = home.layout();
    let _ = ksp::layout::ensure_at(layout.root(), None);

    assert!(
        !layout.imports_ledger().exists(),
        "the table must not create the ledger; the first append does"
    );
}

// ---------------------------------------------------------------------------
// T003 — the ledger is written after the sealed write, never before
// ---------------------------------------------------------------------------

#[test]
fn a_failed_write_leaves_no_ledger_row() {
    // The ordering is the guarantee. A row written before the seal would name a
    // record that does not exist, and the next import would decide `unchanged`
    // against a version nobody can open.
    //
    // Asserted through the public shape rather than by injecting a store
    // failure: `record_import` takes the rows the caller already wrote, so a
    // caller that wrote nothing passes an empty slice and gets no row.
    let home = Home::new("ordering");
    let layout = home.layout();

    record_import(&layout, &[]).expect("an empty import still succeeds");
    let text = std::fs::read_to_string(layout.imports_ledger()).unwrap_or_default();
    assert!(
        text.trim().is_empty(),
        "no write means no row; got {text:?}"
    );
}

// ---------------------------------------------------------------------------
// A path helper the assertion above needs
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_lives_directly_in_the_home_not_under_a_principal() {
    // KDD-1 puts the import ledger in the home, unlike the two principal
    // ledgers: an import is the admin's act, and the admin is the only writer,
    // so a per-principal directory would add a boundary with one occupant.
    let home = Home::new("location");
    let layout = home.layout();

    let expected = layout.root().join("imports.jsonl");
    assert_eq!(
        layout.imports_ledger(),
        expected,
        "the ledger sits in the home, beside the record it describes"
    );
    assert!(
        !Path::new(&expected).starts_with(layout.root().join("p")),
        "the ledger is not a principal's file"
    );
}

// ---------------------------------------------------------------------------
// Review findings: the mode, under a umask, and on a pre-existing file
// ---------------------------------------------------------------------------

#[test]
fn an_existing_wider_ledger_is_narrowed_on_the_next_append() {
    // `open(2)`'s mode applies **only at creation**, so a ledger that already
    // exists at `0644` keeps it however the append is opened. `record_import`
    // therefore narrows unconditionally rather than relying on the creation
    // mode, and this test pins that: a file created by an older build, or by
    // hand, would otherwise stay world-readable for the life of the deployment
    // while every status check reported the row as matching.
    use std::os::unix::fs::PermissionsExt;

    let home = Home::new("widen");
    let layout = home.layout();

    std::fs::write(layout.imports_ledger(), "").unwrap();
    std::fs::set_permissions(
        layout.imports_ledger(),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    record_import(&layout, &[entry("file:/tmp/team1.env", "A", 1)])
        .expect("the append succeeds on an existing ledger");

    let mode = std::fs::metadata(layout.imports_ledger())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "an append must narrow a wider ledger, because an append is the only time \
         this code touches the file"
    );
}
