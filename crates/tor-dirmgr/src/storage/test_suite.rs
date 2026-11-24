//! Tests that every [`Store`] implementation should pass.
//!
//! Each function takes a fresh, empty, read-write store.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::storage::EXPIRATION_DEFAULTS;
use time::OffsetDateTime;
use time::ext::NumericalDuration;
use web_time_compat::SystemTimeExt;

/// Return the current time.
fn now_utc() -> OffsetDateTime {
    SystemTime::get().into()
}

/// Return the valid-after time of the latest non-pending microdesc consensus in `store`.
fn latest_consensus_time(store: &dyn Store) -> Result<Option<OffsetDateTime>> {
    Ok(store
        .latest_consensus_meta(ConsensusFlavor::Microdesc)?
        .map(|m| m.lifetime().valid_after().into()))
}

/// Store, find, mark usable and delete a consensus.
pub(crate) fn consensus(store: &mut dyn Store) -> Result<()> {
    use tor_netdoc::doc::netstatus;

    let now = now_utc();
    let one_hour = 1.hours();

    assert_eq!(latest_consensus_time(store)?, None);

    let cmeta = ConsensusMeta::new(
        netstatus::Lifetime::new(
            now.into(),
            (now + one_hour).into(),
            SystemTime::from(now + one_hour * 2),
        )
        .unwrap(),
        [0xAB; 32],
        [0xBC; 32],
    );

    store.store_consensus(
        &cmeta,
        ConsensusFlavor::Microdesc,
        true,
        "Pretend this is a consensus",
    )?;

    {
        assert_eq!(latest_consensus_time(store)?, None);
        let consensus = store
            .latest_consensus(ConsensusFlavor::Microdesc, None)?
            .unwrap();
        assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
        let consensus = store.latest_consensus(ConsensusFlavor::Microdesc, Some(false))?;
        assert!(consensus.is_none());
    }

    store.mark_consensus_usable(&cmeta)?;

    {
        assert_eq!(latest_consensus_time(store)?, now.into());
        let consensus = store
            .latest_consensus(ConsensusFlavor::Microdesc, None)?
            .unwrap();
        assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
        let consensus = store
            .latest_consensus(ConsensusFlavor::Microdesc, Some(false))?
            .unwrap();
        assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
    }

    {
        let consensus_text = store.consensus_by_meta(&cmeta)?;
        assert_eq!(consensus_text.as_str()?, "Pretend this is a consensus");

        let (is, _cmeta2) = store
            .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
            .unwrap();
        assert_eq!(is.as_str()?, "Pretend this is a consensus");

        let cmeta3 = ConsensusMeta::new(
            netstatus::Lifetime::new(
                now.into(),
                (now + one_hour).into(),
                SystemTime::from(now + one_hour * 2),
            )
            .unwrap(),
            [0x99; 32],
            [0x99; 32],
        );
        assert!(store.consensus_by_meta(&cmeta3).is_err());

        assert!(
            store
                .consensus_by_sha3_digest_of_signed_part(&[0x99; 32])?
                .is_none()
        );
    }

    {
        assert!(
            store
                .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
                .is_some()
        );
        store.delete_consensus(&cmeta)?;
        assert!(
            store
                .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
                .is_none()
        );
    }

    Ok(())
}

/// Store and find authority certificates.
pub(crate) fn authcerts(store: &mut dyn Store) -> Result<()> {
    let now = now_utc();
    let one_hour = 1.hours();

    let keyids = AuthCertKeyIds {
        id_fingerprint: [3; 20].into(),
        sk_fingerprint: [4; 20].into(),
    };
    let keyids2 = AuthCertKeyIds {
        id_fingerprint: [4; 20].into(),
        sk_fingerprint: [3; 20].into(),
    };

    let m1 = AuthCertMeta::new(keyids, now.into(), SystemTime::from(now + one_hour * 24));

    store.store_authcerts(&[(m1, "Pretend this is a cert")])?;

    let certs = store.authcerts(&[keyids, keyids2])?;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs.get(&keyids).unwrap(), "Pretend this is a cert");

    Ok(())
}

/// Store, find, and expire microdescriptors.
pub(crate) fn microdescs(store: &mut dyn Store) -> Result<()> {
    let now = now_utc();
    let one_day = 1.days();

    let d1 = [5_u8; 32];
    let d2 = [7; 32];
    let d3 = [42; 32];
    let d4 = [99; 32];

    let long_ago: OffsetDateTime = now - one_day * 100;
    store.store_microdescs(
        &[
            ("Fake micro 1", &d1),
            ("Fake micro 2", &d2),
            ("Fake micro 3", &d3),
        ],
        long_ago.into(),
    )?;

    store.update_microdescs_listed(&[d2], now.into())?;

    let mds = store.microdescs(&[d2, d3, d4])?;
    assert_eq!(mds.len(), 2);
    assert_eq!(mds.get(&d1), None);
    assert_eq!(mds.get(&d2).unwrap(), "Fake micro 2");
    assert_eq!(mds.get(&d3).unwrap(), "Fake micro 3");
    assert_eq!(mds.get(&d4), None);

    // Now we'll expire.  that should drop everything but d2.
    store.expire_all(&EXPIRATION_DEFAULTS)?;
    let mds = store.microdescs(&[d2, d3, d4])?;
    assert_eq!(mds.len(), 1);
    assert_eq!(mds.get(&d2).unwrap(), "Fake micro 2");

    Ok(())
}

/// Store, find, and expire router descriptors.
#[cfg(feature = "routerdesc")]
pub(crate) fn routerdescs(store: &mut dyn Store) -> Result<()> {
    let now = now_utc();
    let one_day = 1.days();
    let long_ago: OffsetDateTime = now - one_day * 100;
    let recently = now - one_day;

    let d1 = [5_u8; 20];
    let d2 = [7; 20];
    let d3 = [42; 20];
    let d4 = [99; 20];

    store.store_routerdescs(&[
        ("Fake routerdesc 1", long_ago.into(), &d1),
        ("Fake routerdesc 2", recently.into(), &d2),
        ("Fake routerdesc 3", long_ago.into(), &d3),
    ])?;

    let rds = store.routerdescs(&[d2, d3, d4])?;
    assert_eq!(rds.len(), 2);
    assert_eq!(rds.get(&d1), None);
    assert_eq!(rds.get(&d2).unwrap(), "Fake routerdesc 2");
    assert_eq!(rds.get(&d3).unwrap(), "Fake routerdesc 3");
    assert_eq!(rds.get(&d4), None);

    // Now we'll expire.  that should drop everything but d2.
    store.expire_all(&EXPIRATION_DEFAULTS)?;
    let rds = store.routerdescs(&[d2, d3, d4])?;
    assert_eq!(rds.len(), 1);
    assert_eq!(rds.get(&d2).unwrap(), "Fake routerdesc 2");

    Ok(())
}

/// Store and replace protocol recommendations.
pub(crate) fn protocol_statuses(store: &mut dyn Store) -> Result<()> {
    let now = SystemTime::get();
    let hour = 1.hours();

    let valid_after = now;
    let protocols = serde_json::from_str(
        r#"{
            "client":{
                "required":"Link=5 LinkAuth=3",
                "recommended":"Link=1-5 LinkAuth=2-5"
            },
            "relay":{
                "required":"Wombat=20-22 Knish=25-27",
                "recommended":"Wombat=20-30 Knish=20-30"
            }
            }"#,
    )
    .unwrap();

    let v = store.cached_protocol_recommendations()?;
    assert!(v.is_none());

    store.update_protocol_recommendations(valid_after, &protocols)?;
    let v = store.cached_protocol_recommendations()?.unwrap();
    assert_eq!(v.0, now);
    assert_eq!(
        serde_json::to_string(&protocols).unwrap(),
        serde_json::to_string(&v.1).unwrap()
    );

    let protocols2 = serde_json::from_str(
        r#"{
            "client":{
                "required":"Link=5 ",
                "recommended":"Link=1-5"
            },
            "relay":{
                "required":"Wombat=20",
                "recommended":"Cons=6"
            }
            }"#,
    )
    .unwrap();

    let valid_after_2 = now + hour;
    store.update_protocol_recommendations(valid_after_2, &protocols2)?;

    let v = store.cached_protocol_recommendations()?.unwrap();
    assert_eq!(v.0, now + hour);
    assert_eq!(
        serde_json::to_string(&protocols2).unwrap(),
        serde_json::to_string(&v.1).unwrap()
    );

    Ok(())
}

/// Store, find, and expire bridge descriptors.
#[cfg(feature = "bridge-client")]
pub(crate) fn bridgedescs(store: &mut dyn Store) -> Result<()> {
    let now = SystemTime::get();
    let hour = std::time::Duration::from_secs(3600);
    let bridge1: BridgeConfig = "51.68.172.83:9001 EB6EFB27F29AC9511A4246D7ABE1AFABFB416FF1"
        .parse()
        .unwrap();
    let bridge2: BridgeConfig = "192.0.2.1:9001 0123456789ABCDEF0123456789ABCDEF01234567"
        .parse()
        .unwrap();
    let bridge3: BridgeConfig = "192.0.2.2:9001 76543210FEDCBA9876543210FEDCBA9876543210"
        .parse()
        .unwrap();

    assert!(store.lookup_bridgedesc(&bridge1)?.is_none());

    let fresh = CachedBridgeDescriptor::new(now - hour, "Fake bridge descriptor 1".into());
    store.store_bridgedesc(&bridge1, fresh, now + hour * 24)?;
    // Already past the time when we may delete it.
    let stale = CachedBridgeDescriptor::new(now - hour * 48, "Fake bridge descriptor 2".into());
    store.store_bridgedesc(&bridge2, stale, now - hour * 24)?;
    // Apparently fetched in the future.
    let future = CachedBridgeDescriptor::new(now + hour * 48, "Fake bridge descriptor 3".into());
    store.store_bridgedesc(&bridge3, future, now + hour * 72)?;

    let found = store.lookup_bridgedesc(&bridge1)?.unwrap();
    assert_eq!(found.document, "Fake bridge descriptor 1");
    assert_eq!(found.fetched, now - hour);

    store.expire_all(&EXPIRATION_DEFAULTS)?;
    assert!(store.lookup_bridgedesc(&bridge1)?.is_some());
    assert!(store.lookup_bridgedesc(&bridge2)?.is_none());
    assert!(store.lookup_bridgedesc(&bridge3)?.is_none());

    store.delete_bridgedesc(&bridge1)?;
    assert!(store.lookup_bridgedesc(&bridge1)?.is_none());

    Ok(())
}
