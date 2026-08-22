//! Integration tests for identity + record persistence: a stable EndpointId
//! across restarts, and idempotent initialization.

use cawala_node::{identity, record, spawn_with_secret_key};

#[tokio::test]
async fn same_data_dir_produces_same_endpoint_id() {
    let dir = tempfile::tempdir().unwrap();

    // First "run": generate the key, bind, observe the id.
    let key = identity::load_or_create_secret_key(dir.path()).unwrap();
    let router1 = spawn_with_secret_key(key.clone()).await.expect("bind #1");
    let id1 = router1.endpoint().id();
    router1.shutdown().await.expect("shutdown #1");

    // Second "run": reload from disk, bind again, same id.
    let key2 = identity::load_or_create_secret_key(dir.path()).unwrap();
    let router2 = spawn_with_secret_key(key2).await.expect("bind #2");
    let id2 = router2.endpoint().id();
    router2.shutdown().await.expect("shutdown #2");

    assert_eq!(id1, id2, "endpoint id must be stable across restarts");
    assert_eq!(id1.to_string(), key.public().to_string());
}

#[tokio::test]
async fn init_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();

    // First init: identity + record created.
    let key1 = identity::load_or_create_secret_key(dir.path()).unwrap();
    let id1 = key1.public().to_string();
    let store1 = record::RecordStore::open(dir.path(), &id1).unwrap();
    let mut store1 = store1;
    store1
        .attach_child("child-1", cawala_topology::ChildKind::Node, None)
        .unwrap();
    store1.save().unwrap();

    // Second init against the same dir: same identity, record loaded unchanged
    // (mutations from the first run persist, nothing resets).
    let key2 = identity::load_or_create_secret_key(dir.path()).unwrap();
    let id2 = key2.public().to_string();
    assert_eq!(id1, id2, "init must be idempotent (same endpoint id)");
    let store2 = record::RecordStore::open(dir.path(), &id2).unwrap();
    assert_eq!(store1.record(), store2.record(), "record must round-trip");
}
