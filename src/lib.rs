pub trait KeyManagementScheme {
    type Init;
    type Key;
    type Id;

    /// Sets up and returns the key management scheme.
    fn setup(init: Self::Init) -> Self;

    /// Derive the key corresponding to `x`.
    /// This key should not be kept around beyond any updates to `x`.
    fn derive(&mut self, x: Self::Id) -> Self::Key;

    /// Update the key corresponding to `x`.
    /// The old key is truly underivable from `self` after calling `epoch()`.
    fn update(&mut self, x: Self::Id) -> Self::Key;

    /// Makes every updated key truly underivable from `self`.
    fn epoch(&mut self);
}
