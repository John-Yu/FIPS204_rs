use crate::helpers;
use crate::types::Ph;
use crate::Q;
#[cfg(feature = "default-rng")]
use rand_core::OsRng;
use rand_core::{CryptoRng, CryptoRngCore, RngCore}; // Import Vec from alloc

/// The `KeyGen` trait is defined to allow trait objects for keygen.
pub trait KeyGen {
    /// An expanded public key containing precomputed elements to increase (repeated)
    /// verify performance. Derived from the public key.
    type PublicKey;

    /// An expanded private key containing precomputed elements to increase (repeated)
    /// signing performance. Derived from the private key.
    type PrivateKey;

    /// Generates a public and private key pair specific to this security parameter set.
    /// This function utilizes the **provided** random number generator. This function operates
    /// in constant-time relative to secret data (which specifically excludes the provided random
    /// number generator internals, the `rho` value stored in the public key, and the hash-derived
    /// `rho_prime` values that are rejection-sampled/expanded into the internal `s_1` and `s_2` values).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails.
    fn try_keygen_with_rng(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;
    /// Generates a public and private key pair specific to this security parameter set.
    /// This function utilizes the **OS default** random number generator. This function operates
    /// in constant-time relative to secret data (which specifically excludes the OS random
    /// number generator internals, the `rho` value stored in the public key, and the hash-derived
    /// `rho_prime` values that are rejection-sampled/expanded into the internal `s_1` and `s_2` values).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails.
    fn try_keygen() -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
        Self::try_keygen_with_rng(&mut OsRng)
    }
    /// Generates an public and private key key pair specific to this security parameter set
    /// based on a provided seed. <br>
    /// This function operates in constant-time relative to secret data (which specifically excludes
    /// the the `rho` value stored in the public key and the hash-derived `rho_prime` values that are
    /// rejection-sampled/expanded into the internal `s_1` and `s_2` values).
    fn keygen_from_seed(xi: &[u8; 32]) -> (Self::PublicKey, Self::PrivateKey);
}

/// The Signer trait is implemented for the `PrivateKey` struct on each of the security parameter sets.
pub trait Signer {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type Signature;
    /// The public key that corresponds to the private/secret key
    type PublicKey;

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes the **OS default** random number generator.
    /// This function operates in constant-time relative to secret data (which specifically excludes
    /// the OS default random number generator internals, the `rho` value this is stored in the public
    /// key, the hash-derived `rho_prime` values that are rejection-sampled/expanded into the internal
    /// `s_1` and `s_2` values, and the main signing rejection loop as noted in section 5.5 of
    /// <https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf>).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails or the `ctx` is longer than 255 bytes; propagates internal errors.
    ///
    #[cfg(feature = "default-rng")]
    fn try_sign(&self, message: &[u8], ctx: &[u8]) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng(&mut OsRng, message, ctx)
    }
    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes the **provided** random number generator.
    /// This function operates in constant-time relative to secret data (which specifically excludes
    /// the provided random number generator internals, the `rho` value (also) stored in the public
    /// key, the hash-derived `rho_prime` value that is rejection-sampled/expanded into the internal
    /// `s_1` and `s_2` values, and the main signing rejection loop as noted in section 5.5 of
    /// <https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf>.
    ///
    /// # Errors
    /// Returns an error when the random number generator fails or the `ctx` is longer than 255 bytes; propagates internal errors.
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        message: &[u8],
        ctx: &[u8],
    ) -> Result<Self::Signature, &'static str>;
    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes the **provided seed to support (less common)
    /// deterministic signatures**. This function operates in constant-time relative to secret data
    /// (which specifically excludes the `rho` value stored in the public key, the hash-derived
    /// `rho_prime` value that is rejection-sampled/expanded into the internal `s_1` and `s_2` values,
    /// and the main signing rejection loop as noted in section 5.5 of
    /// <https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf>.
    ///
    /// # Errors
    /// Returns an error when the `ctx` is longer than 255 bytes; propagates internal errors.
    fn try_sign_with_seed(
        &self,
        seed: &[u8; 32],
        message: &[u8],
        ctx: &[u8],
    ) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng(&mut DummyRng { data: *seed }, message, ctx)
    }
    /// Attempt to sign the hash of the given message, returning a digital signature on success,
    /// or an error if something went wrong. This function utilizes the **default OS** random number
    /// generator and allows for several hash algorithms. This function operates in constant-time
    /// relative to secret data (which specifically excludes the provided random number generator
    /// internals, the `rho` value (also) stored in the public key, the hash-derived `rho_prime`
    /// value that is rejection-sampled/expanded into the internal `s_1` and `s_2` values, and the
    /// main signing rejection loop as noted in section 5.5 of
    /// <https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf>.
    ///
    /// # Errors
    /// Returns an error when the random number generator fails or the `ctx` is longer than 255 bytes; propagates internal errors.
    #[cfg(feature = "default-rng")]
    fn try_hash_sign(
        &self,
        message: &[u8],
        ctx: &[u8],
        ph: &Ph,
    ) -> Result<Self::Signature, &'static str> {
        self.try_hash_sign_with_rng(&mut OsRng, message, ctx, ph)
    }
    /// Attempt to sign the hash of the given message, returning a digital signature on success,
    /// or an error if something went wrong. This function utilizes the **provided** random number
    /// generator and allows for several hash algorithms. This function operates in constant-time
    /// relative to secret data (which specifically excludes the provided random number generator
    /// internals, the `rho` value (also) stored in the public key, the hash-derived `rho_prime`
    /// value that is rejection-sampled/expanded into the internal `s_1` and `s_2` values, and the
    /// main signing rejection loop as noted in section 5.5 of
    /// <https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf>.
    ///
    /// # Errors
    /// Returns an error when the random number generator fails or the `ctx` is longer than 255 bytes; propagates internal errors.
    fn try_hash_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        message: &[u8],
        ctx: &[u8],
        ph: &Ph,
    ) -> Result<Self::Signature, &'static str>;
    /// Attempt to sign the hash of the given message, returning a digital signature on success,
    /// something went wrong. This function utilizes the **provided seed to support (less common)
    /// deterministic signatures**. This function operates in constant-time relative to secret data
    /// (which specifically excludes the `rho` value stored in the public key, the hash-derived
    /// `rho_prime` value that is rejection-sampled/expanded into the internal `s_1` and `s_2` values,
    /// and the main signing rejection loop as noted in section 5.5 of
    /// <https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf>.
    ///
    /// # Errors
    /// Returns an error when the `ctx` is longer than 255 bytes; propagates internal errors.
    fn try_hash_sign_with_seed(
        &self,
        seed: &[u8; 32],
        message: &[u8],
        ctx: &[u8],
        ph: &Ph,
    ) -> Result<Self::Signature, &'static str> {
        self.try_hash_sign_with_rng(&mut DummyRng { data: *seed }, message, ctx, ph)
    }
    /// Retrieves the public key associated with this private/secret key
    fn get_public_key(&self) -> Self::PublicKey;
}

// This is for the deterministic signing functions; will be refactored more nicely
struct DummyRng {
    data: [u8; 32],
}

impl RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, _out: &mut [u8]) {
        unimplemented!()
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.copy_from_slice(&self.data);
        Ok(())
    }
}

impl CryptoRng for DummyRng {}

/// The Verifier trait is implemented for `PublicKey` on each of the security parameter sets.
pub trait Verifier {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65
    /// or ml-dsa-87
    type Signature;

    /// Verifies a digital signature on a message with respect to a `PublicKey`. As this function
    /// operates on purely public data, it need/does not provide constant-time assurances.
    fn verify(&self, message: &[u8], signature: &Self::Signature, ctx: &[u8]) -> bool;

    /// Verifies a digital signature on the hash of a message with respect to a `PublicKey`. As this
    /// function operates on purely public data, it need/does not provide constant-time assurances.
    fn hash_verify(&self, message: &[u8], sig: &Self::Signature, ctx: &[u8], ph: &Ph) -> bool;
}

/// The `SerDes` trait provides for validated serialization and deserialization of fixed- and correctly-size elements.
///
/// Note that FIPS 204 currently states that outside of exact length checks "ML-DSA is not designed to require any
/// additional public-key validity checks" (perhaps "...designed not to require..." would be better). Nonetheless, a
/// `Result()` is returned during all deserialization operations to preserve the ability to add future checks (and for
/// symmetry across structures). Note that for the current implementation, both of the private and public key
/// deserialization routines invoke an internal decode that catches over-sized coefficients (for early detection).
pub trait SerDes {
    /// The fixed-size byte array to be serialized or deserialized
    type ByteArray;

    /// Produces a byte array of fixed-size specific to the struct being serialized.
    fn into_bytes(self) -> Self::ByteArray;

    /// Consumes a byte array of fixed-size specific to the struct being deserialized; performs validation
    fn try_from_bytes(ba: &Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}

/// A `ParameterSet` captures the parameters that describe a particular instance of ML-DSA.  There
/// are three variants, corresponding to three different security levels.
pub trait ParameterSet {
    /// Number of nonzero values in the polynomial c
    const TAU: i32;
    /// Collision strength of `c_tilde`, in bytes (lambda / 4 in the spec)
    const LAMBDA: usize;
    /// Error size bound for y
    const GAMMA1: i32;
    /// Low-order rounding range
    const GAMMA2: i32;
    /// Number of rows in the A matrix
    const K: usize;
    /// Number of columns in the A matrix
    const L: usize;
    /// Private key range
    const ETA: i32;
    /// Max number of true values in the hint
    const OMEGA: i32;
    /// Private (secret) key length in bytes.
    const SK_LEN: usize;
    /// Public key length in bytes.
    const PK_LEN: usize;
    /// Signature length in bytes.
    const SIG_LEN: usize;

    // -
    /// Beta = Tau * Eta
    const BETA: i32 = Self::TAU * Self::ETA;
    const LAMBDA_DIV4: usize = Self::LAMBDA / 4;
    const W1_LEN: usize = 32 * Self::K * helpers::bit_length((Q - 1) / (2 * Self::GAMMA2) - 1);
    const CTEST: bool = false; // When true, the logic goes into CT test mode

    // ---- types -----
    type PrivateKey;
    type PublicKey;
    type Signature;
    type PrivateKeyEncoded;
    type PublicKeyEncoded;

    // ---- fn -----
    /// # Algorithm: 1 `ML-DSA.KeyGen()` on page 17.
    /// Generates a public-private key pair.
    ///
    /// **Input**: `rng` a cryptographically-secure random number generator. <br>
    /// **Output**: Public key, `pk ∈ B^{32+32·k·(bitlen(q−1)−d)}`, and
    ///             private key, `sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2·η)+d·k)}`
    ///
    /// # Errors
    /// Returns an error when the random number generator fails.
    fn key_gen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;
    /// # Algorithm: 6 `ML-DSA.KeyGen_internal()` on page 15.
    /// Generates a public-private key pair.
    ///
    /// **Input**: `xi` a seed. <br>
    /// **Output**: Public key, `pk ∈ B^{32+32·k·(bitlen(q−1)−d)}`, and
    ///             private key, `sk ∈ B^{32+32+64+32·((ℓ+k)·bitlen(2·η)+d·k)}`
    ///
    fn key_gen_internal(xi: &[u8; 32]) -> (Self::PublicKey, Self::PrivateKey);
    /// # Algorithm 7: ML-DSA.Sign_internal(𝑠𝑘, 𝑀 ′ , 𝑟𝑛𝑑) on page 25.
    /// Deterministic algorithm to generate a signature for a formatted message 𝑀 ′.
    ///
    /// **Input**:  Private key 𝑠𝑘 ∈ 𝔹^{32+32+64+32⋅((ℓ+𝑘)⋅bitlen(2𝜂)+𝑑𝑘)},
    ///             formatted message 𝑀′ ∈ {0, 1}∗, and
    ///             per message randomness or dummy variable rnd ∈ 𝔹^{32}. <br>
    /// **Output**: Signature 𝜎 ∈ 𝔹^{𝜆/4+ℓ⋅32⋅(1+bitlen(𝛾1−1))+𝜔+𝑘}.
    // Note the M' is assembled here from provided elements, rather than by caller.
    // Further, a deserialized private key struct has a variety of pre-computed
    // elements ready-to-go.
    fn sign_internal(
        esk: &Self::PrivateKey,
        message: &[u8],
        ctx: &[u8],
        oid: &[u8],
        phm: &[u8],
        rnd: [u8; 32],
        nist: bool,
    ) -> Self::Signature;
    /// # Algorithm 8: ML-DSA.Verify_internal(𝑝𝑘, 𝑀′, 𝜎) on page 27.
    /// Internal function to verify a signature 𝜎 for a formatted message 𝑀′.
    ///
    /// **Input**:  Public key 𝑝𝑘 ∈ 𝔹^{32+32𝑘(bitlen(𝑞−1)−𝑑),
    ///             message 𝑀′ ∈ {0, 1}∗,
    ///             Signature 𝜎 ∈ 𝔹^{𝜆/4+ℓ⋅32⋅(1+bitlen(𝛾1 −1))+𝜔+𝑘}. <br>
    /// **Output**: Boolean
    // Note the M' is assembled here from provided elements, rather than by caller.
    // Further, a deserialized public key struct has a variety of pre-computed
    // elements ready-to-go.
    fn verify_internal(
        epk: &Self::PublicKey,
        m: &[u8],
        sig: &Self::Signature,
        ctx: &[u8],
        oid: &[u8],
        phm: &[u8],
        nist: bool,
    ) -> bool;
    /// Expand the private/secret key by pre-calculating some constants used in the signing process.
    ///
    /// # Errors
    /// Returns an error on malformed private key.
    fn expand_private(sk: &Self::PrivateKeyEncoded) -> Result<Self::PrivateKey, &'static str>;
    /// Expand the public key by pre-calculating some constants used in the signing process.
    ///
    /// # Errors
    /// Returns an error on malformed public key.
    fn expand_public(pk: &Self::PublicKeyEncoded) -> Result<Self::PublicKey, &'static str>;
    fn public_try_from(v: &[u8]) -> Result<Self::PublicKey, &'static str>;
    fn private_try_from(v: &[u8]) -> Result<Self::PrivateKey, &'static str>;
    /// Encodes a private key struct into its byte array representation
    fn encode_private(sk: &Self::PrivateKey) -> Self::PrivateKeyEncoded;
    /// Encodes a public key struct into its byte array representation
    fn encode_public(pk: &Self::PublicKey) -> Self::PublicKeyEncoded;
    /// Retrieves the public key associated with this private/secret key
    fn private_to_public_key(sk: &Self::PrivateKey) -> Self::PublicKey;
}
