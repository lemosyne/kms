use embedded_io::blocking::{Read, Seek, Write};

/// A trait describing the basic functionality of a key management scheme.
pub trait KeyManagementScheme {
    /// The type of a key.
    type Key;
    /// The type used to act as key identifiers.
    type KeyId;
    /// The associated error for fallible operations (e.g. `persist()`).
    type Error;

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
    fn commit(&mut self) -> Vec<Self::KeyId>;
}

pub trait Persist<IO: Read + Write + Seek>: Sized {
    type Init;

    fn persist(&self, sink: IO) -> Result<(), IO::Error>;
    fn load(&self, init: Self::Init, source: IO) -> Result<Self, IO::Error>;
}
