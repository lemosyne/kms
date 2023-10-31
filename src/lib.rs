use core::fmt::Debug;

/// A trait describing the basic functionality of a key management scheme.
pub trait KeyManagementScheme {
    /// The type of a key.
    type Key;
    /// The type used to act as key identifiers.
    type KeyId;
    /// The associated error for fallible operations (e.g. `persist()`).
    type Error: Debug;
    /// The additional state needed for commit.
    type CommitState;

    /// Derive the key corresponding to the given `KeyId`.
    ///
    /// This key should not be kept beyond any updates to that `KeyId`.
    fn derive(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error>;

    /// Update the key corresponding to the given `KeyId`.
    ///
    /// Revocation of the old key is only guaranteed after calling `commit()`.
    fn update(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error>;

    /// Commits any deferred key updates, guaranteeing their revocation from `self`,
    /// assuming that all keys which persisted `self` in the past are securely deleted.
    fn commit(&mut self, state: CommitState) -> Vec<Self::KeyId>;
}

#[cfg(feature = "persistence")]
use inachus::IoGenerator;

#[cfg(feature = "persistence")]
/// A trait describing the basic functionality of a persisted key management scheme.
pub trait PersistedKeyManagementScheme<IoG: IoGenerator> {
    /// The type of a key.
    type Key;
    /// The type used to act as key identifiers.
    type KeyId;
    /// The associated error for fallible operations (e.g. `persist()`).
    type Error: Debug;

    /// Derive the key corresponding to the given `KeyId`.
    ///
    /// This key should not be kept beyond any updates to that `KeyId`.
    fn derive(&mut self, iog: &mut IoG, key: Self::KeyId) -> Result<Self::Key, Self::Error>;

    /// Update the key corresponding to the given `KeyId`.
    ///
    /// Revocation of the old key is only guaranteed after calling `commit()`.
    fn update(&mut self, iog: &mut IoG, key: Self::KeyId) -> Result<Self::Key, Self::Error>;

    /// Commits any deferred key updates, guaranteeing their revocation from `self`,
    /// assuming that all keys which persisted `self` in the past are securely deleted.
    fn commit(&mut self, iog: &mut IoG) -> Vec<Self::KeyId>;
}
