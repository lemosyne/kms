/// A trait describing the basic functionality of a key management scheme.
pub trait KeyManagementScheme {
    /// The type containing anything required to initialize the key management scheme.
    type Init;
    /// The type of a key.
    type Key;
    /// The type used to act as key identifiers.
    type KeyId;
    /// The associated error for fallible operations (e.g. `persist()`).
    type Error;
    /// Parameters for persisting or loading public state.
    type PublicParams;
    /// Parameters for persisting or loading private state.
    type PrivateParams;

    /// Sets up and returns the key management scheme.
    fn setup(init: Self::Init) -> Self;

    /// Derive the key corresponding to the given `KeyId`.
    ///
    /// This key should not be kept beyond any updates to that `KeyId`.
    fn derive(&mut self, key: Self::KeyId) -> Self::Key;

    /// Derives the keys corresponding to the given `KeyId`s.
    ///
    /// These keys should not be kept beyond any updates to their respective `KeyId`s.
    fn derive_many<I>(&mut self, keys: I) -> Vec<Self::Key>
    where
        I: IntoIterator<Item = Self::KeyId>,
    {
        keys.into_iter().map(|key| self.derive(key)).collect()
    }

    /// Update the key corresponding to the given `KeyId`.
    ///
    /// Revocation of the old key is only guaranteed after calling `commit()`.
    fn update(&mut self, key: Self::KeyId) -> Self::Key;

    /// Updates the keys corresponding to the given `KeyId`s.
    ///
    /// Revocation of the old keys is only guaranteed after calling `commit()`.
    fn update_many<I>(&mut self, keys: I) -> Vec<Self::Key>
    where
        I: IntoIterator<Item = Self::KeyId>,
    {
        keys.into_iter().map(|key| self.update(key)).collect()
    }

    /// Commits any deferred key updates, guaranteeing their revocation from `self`.
    ///
    /// This can be a no-op for schemes that don't implement `DeferredKeyManagementScheme`.
    fn commit(&mut self);

    /// Compacts the internal state of `self`.
    ///
    /// This can be a no-op for schemes that do not or cannot compact internal state.
    fn compact(&mut self);

    /// Persists public state.
    ///
    /// Public state is any data that does not need to be securely deleted.
    fn persist_public_state(&self, params: Self::PublicParams) -> Result<(), Self::Error>;

    /// Persists private state.
    ///
    /// Private state is any data that must be securely deleted.
    fn persist_private_state(&self, params: Self::PrivateParams) -> Result<(), Self::Error>;

    /// Persists public and private state to their respective locations.
    fn persist(
        &self,
        pub_params: Self::PublicParams,
        priv_params: Self::PrivateParams,
    ) -> Result<(), Self::Error> {
        self.persist_public_state(pub_params)?;
        self.persist_private_state(priv_params)?;
        Ok(())
    }

    /// Loads public state from some readable location.
    fn load_public_state(&mut self, params: Self::PublicParams) -> Result<(), Self::Error>;

    /// Loads private state from some readable location.
    fn load_private_state(&mut self, params: Self::PrivateParams) -> Result<(), Self::Error>;

    /// Loads public and private from their respective locations.
    fn load(
        &mut self,
        pub_params: Self::PublicParams,
        priv_params: Self::PrivateParams,
    ) -> Result<(), Self::Error> {
        self.load_private_state(priv_params)?;
        self.load_public_state(pub_params)?;
        Ok(())
    }
}

/// A marker trait used to indicate that a `KeyManagementScheme` implementation is secure.
/// Essentially, this should guarantee that there is only a negligible probability of being able to
/// recover a key that has been updated.
pub trait SecureKeyManagementScheme: KeyManagementScheme {}

/// A marker trait used to indicate that a `KeyManagementScheme` implementation performs
/// fine-grained updates: `update()` only affects the target key.
pub trait FineGrainedKeyManagementScheme: KeyManagementScheme {}

/// A marker trait used to indicate that a `KeyManagementScheme` implementation performs
/// coarse-grained updates: `update()` may affect more keys than just the target key.
pub trait CoarseGrainedKeyManagementScheme: KeyManagementScheme {}

/// A marker trait used to indicate that a `KeyManagementScheme` implementation performs
/// deferred updates: `update()` should be followed by `commit()` for true revocation.
pub trait DeferredKeyManagementScheme: KeyManagementScheme {}
