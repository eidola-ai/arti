//! A directory store that keeps everything in memory.

#[cfg(feature = "routerdesc")]
use super::RdDigest;
use super::{
    AuthCertKeyIds, AuthCertMeta, ConsensusFlavor, ConsensusMeta, ExpirationConfig, InputString,
    MdDigest, ProtoStatuses, Store,
};
#[cfg(feature = "bridge-client")]
use super::{BridgeConfig, CachedBridgeDescriptor};
#[cfg(test)]
use crate::Error;
use crate::Result;

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use web_time_compat::SystemTimeExt as _;

/// A [`Store`] that keeps all of its contents in memory.
///
/// Nothing is persisted: each `MemoryStore` starts out empty,
/// and its contents are lost when it is dropped.
/// It never shares its contents with another store, so it is never read-only.
///
/// This is mainly useful for testing, and for applications that do not
/// want to keep a directory cache between runs.
#[derive(Debug, Default)]
pub struct MemoryStore {
    /// Consensuses, indexed by the SHA3-256 digest of the whole document.
    consensuses: HashMap<[u8; 32], StoredConsensus>,
    /// Authority certificates, with their expiration times.
    authcerts: HashMap<AuthCertKeyIds, (SystemTime, String)>,
    /// Microdescriptors, with the time they were last listed.
    microdescs: HashMap<MdDigest, (SystemTime, String)>,
    /// Router descriptors, with their publication times.
    #[cfg(feature = "routerdesc")]
    routerdescs: HashMap<RdDigest, (SystemTime, String)>,
    /// Bridge descriptors, indexed by bridge line, with the time until which to keep them.
    #[cfg(feature = "bridge-client")]
    bridgedescs: HashMap<String, (CachedBridgeDescriptor, SystemTime)>,
    /// Our latest protocol recommendations, and the valid-after time of their consensus.
    protocol_recommendations: Option<(SystemTime, ProtoStatuses)>,
}

/// A consensus held in a [`MemoryStore`].
#[derive(Debug)]
struct StoredConsensus {
    /// Information about the consensus.
    meta: ConsensusMeta,
    /// The consensus flavor.
    flavor: ConsensusFlavor,
    /// True if we don't yet have enough descriptors to use this consensus.
    pending: bool,
    /// The text of the consensus.
    text: String,
}

impl MemoryStore {
    /// Create a new, empty `MemoryStore`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the stored consensus of `flavor` (and pending status `pending`, if given)
    /// that is valid until the latest time.
    fn latest(&self, flavor: ConsensusFlavor, pending: Option<bool>) -> Option<&StoredConsensus> {
        self.consensuses
            .values()
            .filter(|c| c.flavor == flavor && pending.is_none_or(|p| c.pending == p))
            .max_by_key(|c| c.meta.lifetime().valid_until())
    }
}

/// Return `now - age`, or the earliest representable time if that underflows.
fn cutoff(now: SystemTime, age: Duration) -> SystemTime {
    now.checked_sub(age).unwrap_or(SystemTime::UNIX_EPOCH)
}

impl Store for MemoryStore {
    fn is_readonly(&self) -> bool {
        false
    }

    fn upgrade_to_readwrite(&mut self) -> Result<bool> {
        Ok(true)
    }

    fn expire_all(&mut self, expiration: &ExpirationConfig) -> Result<()> {
        let now = SystemTime::get();

        let microdescs = cutoff(now, expiration.microdescs());
        self.microdescs
            .retain(|_, (listed, _)| *listed >= microdescs);
        let authcerts = cutoff(now, expiration.authcerts());
        self.authcerts
            .retain(|_, (expires, _)| *expires >= authcerts);
        let consensuses = cutoff(now, expiration.consensuses());
        self.consensuses
            .retain(|_, c| c.meta.lifetime().valid_until() >= consensuses);
        #[cfg(feature = "routerdesc")]
        {
            let routerdescs = cutoff(now, expiration.router_descs());
            self.routerdescs
                .retain(|_, (published, _)| *published >= routerdescs);
        }
        // Bridges might send us crazy times, so discard anything from the future too.
        #[cfg(feature = "bridge-client")]
        self.bridgedescs
            .retain(|_, (entry, until)| now <= *until && entry.fetched <= now);

        Ok(())
    }

    fn latest_consensus(
        &self,
        flavor: ConsensusFlavor,
        pending: Option<bool>,
    ) -> Result<Option<InputString>> {
        Ok(self
            .latest(flavor, pending)
            .map(|c| InputString::from(c.text.clone())))
    }

    fn latest_consensus_meta(&self, flavor: ConsensusFlavor) -> Result<Option<ConsensusMeta>> {
        Ok(self.latest(flavor, Some(false)).map(|c| c.meta.clone()))
    }

    #[cfg(test)]
    fn consensus_by_meta(&self, cmeta: &ConsensusMeta) -> Result<InputString> {
        self.consensus_by_sha3_digest_of_signed_part(cmeta.sha3_256_of_signed())?
            .map(|(text, _)| text)
            .ok_or(Error::CacheCorruption(
                "couldn't find a consensus we thought we had.",
            ))
    }

    fn consensus_by_sha3_digest_of_signed_part(
        &self,
        d: &[u8; 32],
    ) -> Result<Option<(InputString, ConsensusMeta)>> {
        Ok(self
            .consensuses
            .values()
            .find(|c| c.meta.sha3_256_of_signed() == d)
            .map(|c| (InputString::from(c.text.clone()), c.meta.clone())))
    }

    fn store_consensus(
        &mut self,
        cmeta: &ConsensusMeta,
        flavor: ConsensusFlavor,
        pending: bool,
        contents: &str,
    ) -> Result<()> {
        self.consensuses.insert(
            *cmeta.sha3_256_of_whole(),
            StoredConsensus {
                meta: cmeta.clone(),
                flavor,
                pending,
                text: contents.to_owned(),
            },
        );
        Ok(())
    }

    fn mark_consensus_usable(&mut self, cmeta: &ConsensusMeta) -> Result<()> {
        if let Some(c) = self.consensuses.get_mut(cmeta.sha3_256_of_whole()) {
            c.pending = false;
        }
        Ok(())
    }

    fn delete_consensus(&mut self, cmeta: &ConsensusMeta) -> Result<()> {
        self.consensuses.remove(cmeta.sha3_256_of_whole());
        Ok(())
    }

    fn authcerts(&self, certs: &[AuthCertKeyIds]) -> Result<HashMap<AuthCertKeyIds, String>> {
        Ok(certs
            .iter()
            .filter_map(|ids| {
                self.authcerts
                    .get(ids)
                    .map(|(_, text)| (*ids, text.clone()))
            })
            .collect())
    }

    fn store_authcerts(&mut self, certs: &[(AuthCertMeta, &str)]) -> Result<()> {
        for (meta, text) in certs {
            self.authcerts
                .insert(*meta.key_ids(), (meta.expires(), (*text).to_owned()));
        }
        Ok(())
    }

    fn microdescs(&self, digests: &[MdDigest]) -> Result<HashMap<MdDigest, String>> {
        Ok(digests
            .iter()
            .filter_map(|d| self.microdescs.get(d).map(|(_, text)| (*d, text.clone())))
            .collect())
    }

    fn store_microdescs(&mut self, digests: &[(&str, &MdDigest)], when: SystemTime) -> Result<()> {
        for (text, d) in digests {
            self.microdescs.insert(**d, (when, (*text).to_owned()));
        }
        Ok(())
    }

    fn update_microdescs_listed(&mut self, digests: &[MdDigest], when: SystemTime) -> Result<()> {
        for d in digests {
            if let Some((listed, _)) = self.microdescs.get_mut(d) {
                *listed = (*listed).max(when);
            }
        }
        Ok(())
    }

    #[cfg(feature = "routerdesc")]
    fn routerdescs(&self, digests: &[RdDigest]) -> Result<HashMap<RdDigest, String>> {
        Ok(digests
            .iter()
            .filter_map(|d| self.routerdescs.get(d).map(|(_, text)| (*d, text.clone())))
            .collect())
    }

    #[cfg(feature = "routerdesc")]
    fn store_routerdescs(&mut self, digests: &[(&str, SystemTime, &RdDigest)]) -> Result<()> {
        for (text, published, d) in digests {
            self.routerdescs
                .insert(**d, (*published, (*text).to_owned()));
        }
        Ok(())
    }

    #[cfg(feature = "bridge-client")]
    fn lookup_bridgedesc(&self, bridge: &BridgeConfig) -> Result<Option<CachedBridgeDescriptor>> {
        Ok(self
            .bridgedescs
            .get(&bridge.to_string())
            .map(|(entry, _)| entry.clone()))
    }

    #[cfg(feature = "bridge-client")]
    fn store_bridgedesc(
        &mut self,
        bridge: &BridgeConfig,
        entry: CachedBridgeDescriptor,
        until: SystemTime,
    ) -> Result<()> {
        self.bridgedescs.insert(bridge.to_string(), (entry, until));
        Ok(())
    }

    #[cfg(feature = "bridge-client")]
    fn delete_bridgedesc(&mut self, bridge: &BridgeConfig) -> Result<()> {
        self.bridgedescs.remove(&bridge.to_string());
        Ok(())
    }

    fn update_protocol_recommendations(
        &mut self,
        valid_after: SystemTime,
        protocols: &ProtoStatuses,
    ) -> Result<()> {
        self.protocol_recommendations = Some((valid_after, protocols.clone()));
        Ok(())
    }

    fn cached_protocol_recommendations(&self) -> Result<Option<(SystemTime, ProtoStatuses)>> {
        Ok(self.protocol_recommendations.clone())
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::storage::test_suite;

    #[test]
    fn readwrite() -> Result<()> {
        let mut store = MemoryStore::new();
        assert!(!store.is_readonly());
        assert!(store.upgrade_to_readwrite()?);
        Ok(())
    }

    #[test]
    fn consensus() -> Result<()> {
        test_suite::consensus(&mut MemoryStore::new())
    }

    #[test]
    fn authcerts() -> Result<()> {
        test_suite::authcerts(&mut MemoryStore::new())
    }

    #[test]
    fn microdescs() -> Result<()> {
        test_suite::microdescs(&mut MemoryStore::new())
    }

    #[test]
    #[cfg(feature = "routerdesc")]
    fn routerdescs() -> Result<()> {
        test_suite::routerdescs(&mut MemoryStore::new())
    }

    #[test]
    #[cfg(feature = "bridge-client")]
    fn bridgedescs() -> Result<()> {
        test_suite::bridgedescs(&mut MemoryStore::new())
    }

    #[test]
    fn protocol_statuses() -> Result<()> {
        test_suite::protocol_statuses(&mut MemoryStore::new())
    }
}
