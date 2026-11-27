use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

pub(crate) type Fields = Map<String, Value>;
const REVISION: &str = "_prefsRevision";
const VERSIONS: &str = "_prefsFieldVersions";

pub(crate) async fn load(state: &crate::AppState, user: &str) -> Result<Fields, String> {
    use crate::UserSecretLoad::*;
    let text = match crate::load_user_secret(state, user, "preferences.enc").await {
        Plain(text) => text,
        Locked => return Err(crate::PREFERENCES_VAULT_LOCKED.into()),
        Undecryptable(_) => return Err("Could not decrypt preferences.".into()),
        Missing => {
            let dir = std::path::Path::new(&state.data_dir)
                .join("users")
                .join(crate::safe_username(user));
            // The shared secret reader also returns Missing on a read error. A
            // permissions or I/O failure must not turn an existing file into defaults.
            match tokio::fs::metadata(dir.join("preferences.enc")).await {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err("Could not read preferences.".into()),
            }
            match tokio::fs::read_to_string(dir.join("preferences.json")).await {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Fields::new()),
                Err(_) => return Err("Could not read preferences.".into()),
            }
        }
    };
    serde_json::from_str(&text).map_err(|_| "Invalid stored preferences.".into())
}

pub(crate) fn revision(fields: &Fields) -> u64 {
    if !fields.get(VERSIONS).is_some_and(Value::is_object) {
        return 0;
    }
    fields
        .get(REVISION)
        .and_then(Value::as_u64)
        .filter(|value| *value < (1 << 53) - 1)
        .unwrap_or(0)
}

// Cached browsers do not send their base revision. Remember only what this
// authenticated socket explicitly loaded and which groups it wrote. An unsolicited
// broadcast may still be in flight when the browser submits its next snapshot.
#[derive(Default)]
pub(crate) struct SocketBasis {
    loaded: u64,
    known: HashMap<String, u64>,
}

impl SocketBasis {
    pub(crate) fn reset(&mut self, revision: u64) {
        self.loaded = revision;
        // The user can click Unfavorite before the browser handles the echo
        // of its own Favorite. A concurrent load must preserve that provenance.
        self.known
            .retain(|name, written| name == "_favsTs" && *written <= revision);
    }
}

// Keep each value and the browser's synchronization metadata indivisible.
fn group(key: &str) -> &str {
    match key {
        "favorites" => "_favsTs",
        "muted" => "_mutedTs",
        "monitor" | "monitorNotifs" | "monitorPush" => "_monitorTs",
        "unread" | "unreadAsOf" | "lastRead" => "unread",
        "mentions" | "_mentionsClearTs" => "_mentionsTs",
        "_ihV" => "inputHistory",
        "queries" => "_queriesTs",
        "closedQueries" => "_closedQueriesTs",
        "ignoreList" => "_ignoreListTs",
        "pmAllow" => "_pmAllowTs",
        "pmBlock" | "pmCooldown" | "pmNotify" | "pmDeliverFirst" => "_pmSettingsTs",
        "pmNet" => "_pmNetTs",
        "highlightWords" => "_highlightWordsTs",
        "favsOnly" => "_favsOnlyTs",
        "userNotes" => "_userNotesTs",
        "channelKeys" => "_channelKeysTs",
        "keepnicks" => "_keepnicksTs",
        "networkOrder" => "_networkOrderTs",
        "tlsVerify" => "_tlsVerifyTs",
        field => field,
    }
}

fn notices(fields: &Fields, fallback: Option<&Fields>) -> (u64, u64) {
    let time = |k| {
        fields
            .get(k)
            .or_else(|| fallback.and_then(|p| p.get(k)))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    (time("_mentionsClearTs"), time("_mentionsTs"))
}

// An explicit JSON null from the settings API means Clear. Both current and
// archived browsers only adopt the map/list form for these fields.
fn normalize_clears(fields: &mut Fields) {
    if fields.get("channelKeys") == Some(&Value::Null) {
        fields.insert("channelKeys".into(), Value::Object(Fields::new()));
    }
    if fields.get("inputHistory") == Some(&Value::Null) {
        fields.insert("inputHistory".into(), Value::Array(Vec::new()));
    }
}

pub(crate) fn browser_json(mut fields: Fields) -> String {
    fields.remove(VERSIONS);
    normalize_clears(&mut fields);
    Value::Object(fields).to_string()
}

pub(crate) fn remove_metadata(fields: &mut Fields) {
    fields.remove(VERSIONS);
    fields.remove(REVISION);
}

pub(crate) struct Merged {
    pub(crate) fields: Fields,
    acknowledged: HashMap<String, u64>,
}

impl Merged {
    // Call only after the account's atomic write succeeded.
    pub(crate) fn acknowledge(&self, socket: &mut SocketBasis) {
        socket.known.extend(self.acknowledged.clone());
    }
}

// Call under the account preferences lock. MCP supplies only its explicit patch
// against the current document. Web browsers supply a filtered snapshot and the
// revision they actually applied. Clocks contain only group names and numbers.
pub(crate) fn merge(
    mut stored: Fields,
    mut incoming: Fields,
    socket: Option<(&SocketBasis, Option<u64>)>,
) -> Merged {
    let current = revision(&stored);
    normalize_clears(&mut stored);
    let canonical_clear = ["channelKeys", "inputHistory"]
        .iter()
        .any(|key| incoming.get(*key) == Some(&Value::Null));
    normalize_clears(&mut incoming);
    let base = socket.map_or(current, |(s, supplied)| supplied.unwrap_or(s.loaded));
    let base = if base <= current { base } else { 0 };
    let mut versions = match stored.remove(VERSIONS) {
        Some(Value::Object(map)) => map,
        _ => Fields::new(),
    };
    versions.retain(|_, value| value.as_u64().is_some_and(|rev| rev <= current));
    let old_notices = notices(&stored, None);
    let incoming_notices = notices(&incoming, socket.is_none().then_some(&stored));
    // An older client's unfiltered recall list must never inherit the current
    // client's assertion that its lines were screened for E2E plaintext.
    let unfiltered_history = incoming
        .get("inputHistory")
        .and_then(Value::as_array)
        .is_some_and(|lines| !lines.is_empty())
        && incoming.get("_ihV").and_then(Value::as_u64).unwrap_or(0) < 2;
    if !incoming.get("inputHistory").is_some_and(Value::is_array) {
        incoming.remove("_ihV");
    }
    let token = incoming.remove("_saveTs");
    remove_metadata(&mut incoming);
    stored.remove("_saveTs");
    let mut corrected = canonical_clear;
    let newer_favorite = incoming.get("favorites").is_some_and(Value::is_array)
        && incoming.get("_favsTs").and_then(Value::as_u64)
            > stored.get("_favsTs").and_then(Value::as_u64);
    // An unversioned client can also prove it received a change by echoing
    // every persisted field of that group unchanged. Its next deliberate edit
    // then works normally. A full stale snapshot cannot acknowledge a secret
    // or private-history group whose contents it still has wrong.
    let mut acknowledged = HashMap::new();
    if let Some((_, None)) = socket {
        let mut unmatched = HashSet::new();
        for (key, value) in &stored {
            let name = group(key);
            let Some(version) = versions
                .get(name)
                .and_then(Value::as_u64)
                .filter(|v| *v > base)
            else {
                continue;
            };
            if incoming.get(key) == Some(value) {
                acknowledged.insert(name.to_owned(), version);
            } else {
                unmatched.insert(name);
            }
        }
        acknowledged.retain(|name, _| !unmatched.contains(name.as_str()));
    }
    // restorePreferences uses these group timestamps to apply a replacement.
    // A slower device's edit must still reach a faster sibling. Check cached
    // clients' actual echoes above before correcting their timestamps.
    for timestamp in [
        "_favsTs", "_mutedTs", "_monitorTs", "_closedQueriesTs", "_ignoreListTs",
        "_pmAllowTs", "_pmSettingsTs", "_pmNetTs", "_highlightWordsTs", "_favsOnlyTs",
        "_userNotesTs", "_channelKeysTs", "_keepnicksTs", "_networkOrderTs", "_tlsVerifyTs",
    ] {
        if !incoming.keys().any(|key| group(key) == timestamp) {
            continue;
        }
        let previous = stored.get(timestamp).and_then(Value::as_u64).unwrap_or(0);
        let submitted = incoming.get(timestamp).and_then(Value::as_u64).unwrap_or(0);
        // TLS reminder sets merge on a tie. A real removal needs a later stamp
        // so that a cached page can replace its set.
        let minimum = if timestamp == "_tlsVerifyTs" && stored.contains_key("tlsVerify")
            && incoming.get("tlsVerify").is_some_and(|value| Some(value) != stored.get("tlsVerify"))
        { previous.saturating_add(1) } else { previous };
        if submitted < minimum {
            incoming.insert(timestamp.into(), Value::from(minimum));
            corrected = true;
        }
    }
    let mut changed = HashSet::new();
    for (key, value) in incoming {
        if stored.get(&key) == Some(&value) {
            continue;
        }
        let name = group(&key);
        let version = versions.get(name).and_then(Value::as_u64).unwrap_or(0);
        let own = socket.is_some_and(|(s, _)| {
            s.known.get(name) == Some(&version)
                && (name != "_favsTs" || version > s.loaded || newer_favorite)
        });
        if (name == "_mentionsTs" && incoming_notices < old_notices)
            || (name == "inputHistory" && unfiltered_history)
            || (version > base
                && !own
                && !(name == "_mentionsTs" && incoming_notices > old_notices))
        {
            corrected = true;
            continue;
        }
        changed.insert(name.to_owned());
        stored.insert(key, value);
    }
    let next = if changed.is_empty() {
        current
    } else {
        current + 1
    };
    for name in &changed {
        versions.insert(name.clone(), Value::from(next));
        acknowledged.insert(name.clone(), next);
    }
    stored.insert(REVISION.into(), Value::from(next));
    stored.insert(VERSIONS.into(), Value::Object(versions));
    if !corrected {
        if let Some(token) = token {
            stored.insert("_saveTs".into(), token);
        }
    }
    Merged {
        fields: stored,
        acknowledged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fields(value: Value) -> Fields {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn independent_browser_changes_survive_both_frame_formats() {
        let original = fields(json!({"giphyKey":"old synthetic key", "autoRejoin":true,
            "channelKeys":{"local":"synthetic"}, "_channelKeysTs":1,
            "inputHistory":["synthetic previously shared line"], "_ihV":2, "favorites":[]}));
        for explicit in [None, Some(0)] {
            let mut socket = SocketBasis::default();
            socket.reset(revision(&original));
            let changed = merge(
                original.clone(),
                fields(json!({"giphyKey":"", "autoRejoin":false,
                "channelKeys":{}, "_channelKeysTs":2, "inputHistory":[], "_ihV":2})),
                None,
            );
            let mut stale = original.clone();
            stale.extend(fields(
                json!({"favorites":["#test"],"_favsTs":7,"_saveTs":"first",
                "_prefsRevision":999,"_prefsFieldVersions":{"giphyKey":0}}),
            ));
            let merged = merge(changed.fields, stale.clone(), Some((&socket, explicit)));
            assert_eq!(merged.fields["favorites"], json!(["#test"]));
            assert_eq!(merged.fields["autoRejoin"], false);
            assert_eq!(merged.fields["channelKeys"], json!({}));
            assert_eq!(merged.fields["_channelKeysTs"], 2);
            assert_eq!(merged.fields["giphyKey"], "");
            assert_eq!(merged.fields["inputHistory"], json!([]));
            assert!(!merged.fields.contains_key("_saveTs"));
            let metadata = merged.fields[VERSIONS].as_object().unwrap();
            assert!(metadata.values().all(|v| v.as_u64().is_some()));
            merged.acknowledge(&mut socket);
            stale.insert("favorites".into(), json!([]));
            let next = merge(merged.fields, stale, Some((&socket, explicit)));
            assert_eq!(next.fields["favorites"], json!([]));
            assert_eq!(next.fields["inputHistory"], json!([]));
            assert_eq!(next.fields["giphyKey"], "");
            let acknowledged = revision(&next.fields);
            socket.reset(acknowledged);
            let intended = merge(
                next.fields,
                fields(json!({"giphyKey":"new synthetic key"})),
                Some((&socket, explicit.map(|_| acknowledged))),
            );
            assert_eq!(intended.fields["giphyKey"], "new synthetic key");
            let browser = browser_json(intended.fields);
            assert!(!browser.contains(VERSIONS));
            assert!(!browser.contains("previously shared line"));
        }
    }

    #[test]
    fn cached_client_can_edit_an_independently_updated_group_after_echoing_it() {
        let mut old = SocketBasis::default();
        let changed = merge(
            Fields::new(),
            fields(json!({"channelKeys":{}, "_channelKeysTs":10})),
            None,
        );
        // Seeing and sending only the timestamp does not prove the key map was applied.
        let partial = merge(
            changed.fields,
            fields(json!({"_channelKeysTs":10})),
            Some((&old, None)),
        );
        partial.acknowledge(&mut old);
        // A matching value with an older timestamp does not acknowledge the
        // intervening write, even when the reply corrects the timestamp.
        let old_stamp = merge(
            partial.fields,
            fields(json!({"channelKeys":{}, "_channelKeysTs":1})),
            Some((&old, None)),
        );
        old_stamp.acknowledge(&mut old);
        let stale = merge(
            old_stamp.fields,
            fields(json!({"channelKeys":{"x":"synthetic"}})),
            Some((&old, None)),
        );
        assert_eq!(stale.fields["channelKeys"], json!({}));
        let seen = merge(
            stale.fields,
            fields(json!({"channelKeys":{}, "_channelKeysTs":10})),
            Some((&old, None)),
        );
        seen.acknowledge(&mut old);
        let deliberate = merge(
            seen.fields,
            fields(json!({"channelKeys":{"x":"new"},"_channelKeysTs":11})),
            Some((&old, None)),
        );
        assert_eq!(deliberate.fields["channelKeys"], json!({"x":"new"}));
    }

    #[test]
    fn unrelated_save_cannot_rewind_favorites_or_block_a_cached_clients_next_click() {
        let mut author = SocketBasis::default();
        let removed = merge(
            Fields::new(),
            fields(json!({"favorites":[], "_favsTs":210})),
            Some((&author, None)),
        );
        removed.acknowledge(&mut author);
        let first = revision(&removed.fields);
        let other = SocketBasis::default();
        let sibling = merge(
            removed.fields,
            fields(json!({"favorites":[],"_favsTs":0,"autoRejoin":false})),
            Some((&other, Some(first))),
        );
        assert_eq!(sibling.fields["_favsTs"], 210);
        let clicked = merge(
            sibling.fields,
            fields(json!({"favorites":["#a"],"_favsTs":220})),
            Some((&author, None)),
        );
        assert_eq!(clicked.fields["favorites"], json!(["#a"]));
        assert_eq!(clicked.fields["_favsTs"], 220);
        assert_eq!(clicked.fields["autoRejoin"], false);
    }

    #[test]
    fn queued_favorite_click_survives_its_authors_load_without_replaying_other_fields() {
        let mut author = SocketBasis::default();
        let added = merge(
            fields(json!({"giphyKey":"fixture", "inputHistory":["test"], "_ihV":2})),
            fields(json!({"favorites":["#one"], "_favsTs":20})),
            Some((&author, Some(0))),
        );
        added.acknowledge(&mut author);
        author.reset(revision(&added.fields));
        let cleared = merge(
            added.fields,
            fields(json!({"giphyKey":"", "inputHistory":[]})),
            None,
        );
        let snapshot = |stamp| {
            fields(json!({
                "favorites":[], "_favsTs":stamp, "giphyKey":"fixture",
                "inputHistory":["test"], "_ihV":2
            }))
        };
        for stamp in [10, 20] {
            let replay = merge(
                cleared.fields.clone(),
                snapshot(stamp),
                Some((&author, Some(0))),
            );
            assert_eq!(replay.fields["favorites"], json!(["#one"]));
        }
        let removed = merge(cleared.fields, snapshot(21), Some((&author, Some(0))));
        assert_eq!(removed.fields["favorites"], json!([]));
        assert_eq!(removed.fields["giphyKey"], "");
        assert_eq!(removed.fields["inputHistory"], json!([]));
        removed.acknowledge(&mut author);
        let sibling = merge(
            removed.fields,
            fields(json!({"favorites":["#two"], "_favsTs":22})),
            None,
        );
        let stale = merge(sibling.fields, snapshot(23), Some((&author, Some(0))));
        assert_eq!(stale.fields["favorites"], json!(["#two"]));
    }

    #[test]
    fn a_slow_devices_privacy_decisions_reach_a_faster_sibling() {
        let original = fields(json!({
            "ignoreList":[], "_ignoreListTs":500, "pmAllow":["contact"], "_pmAllowTs":500,
            "pmBlock":false, "pmNotify":true, "_pmSettingsTs":500,
            "pmNet":{"network":{"override":false}}, "_pmNetTs":500,
            "tlsVerify":{"flipped":["network"], "dismissed":[]}, "_tlsVerifyTs":500
        }));
        let saved = merge(Fields::new(), original.clone(), None);
        let slow = SocketBasis::default();
        let prior = revision(&saved.fields);
        let edit = fields(json!({
            "ignoreList":["ignored"], "_ignoreListTs":100, "pmAllow":[], "_pmAllowTs":100,
            "pmBlock":true, "_pmSettingsTs":100,
            "pmNet":{"network":{"override":true}}, "_pmNetTs":100,
            "tlsVerify":{"flipped":[], "dismissed":["network"]}, "_tlsVerifyTs":100
        }));
        let synced = merge(saved.fields, edit, Some((&slow, Some(prior))));
        for timestamp in ["_ignoreListTs","_pmAllowTs","_pmSettingsTs","_pmNetTs"] {
            assert_eq!(synced.fields[timestamp], 500);
        }
        assert_eq!(synced.fields["_tlsVerifyTs"], 501);
        let stale = merge(synced.fields.clone(), original, Some((&slow, Some(prior))));
        assert_eq!(stale.fields, synced.fields);
        assert_eq!(stale.fields["ignoreList"], json!(["ignored"]));
        assert_eq!(stale.fields["pmAllow"], json!([]));
        assert_eq!(stale.fields["pmBlock"], true);
        assert_eq!(stale.fields["pmNotify"], true);
        assert_eq!(stale.fields["pmNet"]["network"]["override"], true);
        assert_eq!(stale.fields["tlsVerify"]["flipped"], json!([]));
    }

    #[test]
    fn a_fast_devices_unrelated_save_preserves_a_slower_devices_ui_edits() {
        let slow_time = 1_700_000_000_000u64;
        let fast_time = slow_time + 10 * 60 * 1000;
        let original = fields(json!({
            "userNotes": {}, "muted": {}, "monitor": {"old": {"nick": "old"}},
            "monitorNotifs": "on", "monitorPush": "on", "closedQueries": {},
            "highlightWords": ["old"], "favsOnly": true,
            "keepnicks": {"network": {"active": true, "nick": "fixture"}},
            "networkOrder": ["first", "second"]
        }));
        let edited = fields(json!({
            "userNotes": {"contact": "remember this"}, "muted": {"network/#room": true},
            "monitor": {}, "monitorNotifs": "off", "monitorPush": "off",
            "closedQueries": {"network|contact": 7}, "highlightWords": [],
            "favsOnly": false, "keepnicks": {}, "networkOrder": ["second", "first"]
        }));
        let with_stamps = |values: &Fields, time: u64| {
            let mut snapshot = values.clone();
            for key in values.keys() {
                snapshot.insert(group(key).into(), json!(time));
            }
            snapshot
        };
        for explicit in [false, true] {
            let mut fast = SocketBasis::default();
            let mut local = with_stamps(&original, fast_time);
            let first = merge(
                Fields::new(),
                local.clone(),
                Some((&fast, explicit.then_some(0))),
            );
            first.acknowledge(&mut fast);
            let mut slow = SocketBasis::default();
            slow.reset(revision(&first.fields));
            let mut edit = with_stamps(&edited, slow_time);
            edit.insert("_saveTs".into(), json!("slow"));
            let synced = merge(
                first.fields,
                edit,
                Some((&slow, explicit.then_some(slow.loaded))),
            );
            let latest = revision(&synced.fields);

            // A load gives both browser formats the new revision, even if their
            // local timestamp makes them skip the corresponding preference.
            fast.reset(latest);
            for key in edited.keys() {
                let stamp = group(key);
                if synced.fields[stamp].as_u64().unwrap() >= fast_time {
                    local.insert(key.clone(), synced.fields[key].clone());
                    local.insert(stamp.into(), synced.fields[stamp].clone());
                }
            }
            local.insert("autoRejoin".into(), json!(false));
            let saved = merge(
                synced.fields.clone(),
                local,
                Some((&fast, explicit.then_some(latest))),
            );
            let lost: Vec<_> = edited
                .keys()
                .filter(|key| saved.fields[*key] != edited[*key])
                .collect();
            assert!(lost.is_empty(), "unrelated save lost {lost:?}");
            for key in edited.keys() {
                assert_eq!(saved.fields[group(key)], fast_time);
            }
            assert_eq!(saved.fields["autoRejoin"], false);
            assert!(!synced.fields.contains_key("_saveTs"));
        }
    }

    #[test]
    fn a_slow_devices_channel_key_clear_reaches_cached_clients() {
        let mut slow = SocketBasis::default();
        let fast = merge(
            Fields::new(),
            fields(json!({"channelKeys":{"x":"synthetic"}, "_channelKeysTs":500})),
            None,
        );
        slow.reset(revision(&fast.fields));
        let cleared = merge(
            fast.fields,
            fields(json!({"channelKeys":{}, "_channelKeysTs":100,"_saveTs":"slow"})),
            Some((&slow, None)),
        );
        assert_eq!(cleared.fields["channelKeys"], json!({}));
        assert_eq!(cleared.fields["_channelKeysTs"], 500);
        assert!(!cleared.fields.contains_key("_saveTs"));
        let explicit = merge(
            fields(
                json!({"channelKeys":{"x":"synthetic"}, "_channelKeysTs":700,"inputHistory":["old synthetic line"],"_ihV":2}),
            ),
            fields(json!({"channelKeys":null,"inputHistory":null})),
            None,
        );
        assert_eq!(explicit.fields["channelKeys"], json!({}));
        assert_eq!(explicit.fields["_channelKeysTs"], 700);
        assert_eq!(explicit.fields["inputHistory"], json!([]));
    }

    #[test]
    fn unfiltered_history_cannot_inherit_an_existing_privacy_marker() {
        let protected = fields(json!({"inputHistory":["ordinary public line"],"_ihV":2}));
        let legacy =
            fields(json!({"inputHistory":["synthetic private recall"],"favorites":["#test"]}));
        let merged = merge(protected, legacy, Some((&SocketBasis::default(), None)));
        assert_eq!(
            merged.fields["inputHistory"],
            json!(["ordinary public line"])
        );
        assert_eq!(merged.fields["_ihV"], 2);
        assert_eq!(merged.fields["favorites"], json!(["#test"]));
        let marker_only = merge(
            fields(json!({"inputHistory":["legacy unscreened line"]})),
            fields(json!({"_ihV":2})),
            None,
        );
        assert!(!marker_only.fields.contains_key("_ihV"));
    }

    #[test]
    fn legacy_clear_wins_and_new_explicit_notice_patch_keeps_its_generation() {
        let legacy = SocketBasis::default();
        let original = fields(json!({"mentions":[],"_mentionsClearTs":90,"_mentionsTs":91}));
        let stale = merge(
            original,
            fields(json!({"mentions":["old"], "_mentionsTs":100,
            "favorite_test":true,"_saveTs":"stale"})),
            Some((&legacy, None)),
        );
        assert_eq!(stale.fields["mentions"], json!([]));
        assert!(!stale.fields.contains_key("_saveTs"));
        assert_eq!(stale.fields["favorite_test"], true);
        let patch = merge(
            stale.fields,
            fields(json!({"mentions":["new"], "_mentionsTs":120})),
            None,
        );
        assert_eq!(patch.fields["mentions"], json!(["new"]));
        assert_eq!(patch.fields["_mentionsClearTs"], 90);
    }
}
