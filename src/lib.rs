#![no_std]

// Implements FIPS 204 Module-Lattice-Based Digital Signature Standard.
// See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>

// Functionality map per FIPS 204
//
// Algorithm 1 ML-DSA.KeyGen() on page 17                   --> from lib.rs to ml_dsa.rs
// Algorithm 2 ML-DSA.Sign(sk,M,ctx) on page 18             --> lib.rs
// Algorithm 3 ML-DSA.Verify(pk,M,s,ctx) on page 18         --> lib.rs
// Algorithm 4 HashML-DSA.Sign(sk,M,ctx,PH) on page 20      --> lib.rs
// Algorithm 5 HashML-DSA.Verify(sk,M,s,ctx,PH) on page 21  --> lib.rs
// Algorithm 6 ML-DSA.KeyGen_internal(x) on page 23         --> ml_dsa.rs
// Algorithm 7 ML-DSA.Sign_internal(sk,M',rnd) on page 25   --> ml_dsa.rs
// Algorithm 8 ML-DSA.Verify_internal(pk,M',s) on page 27   --> ml_dsa.rs
// Algorithm 9 IntegerToBits(x,a) one page 28               --> (optimized away) conversion.rs
// Algorithm 10 BitsToInteger(y,a) on page 28               --> (optimized away) conversion.rs
// Algorithm 11 IntegerToBytes(x,a) on page 28              --> (optimized away) conversion.rs
// Algorithm 12 BitsToBytes(y) on page 29                   --> (optimized away) conversion.rs
// Algorithm 13 BytesToBits(z) on page 29                   --> (optimized away) conversion.rs
// Algorithm 14 CoefFromThreeBytes(b0,b1,b2) on page 29     --> conversion.rs
// Algorithm 15 CoefFromHalfByte(b) on page 30              --> conversion.rs
// Algorithm 16 SimpleBitPack(w,b) on page 30               --> conversion.rs
// Algorithm 17 BitPack(w,a,b) on page 30                   --> conversion.rs
// Algorithm 18 SimpleBitUnpack(v,b) on page 31             --> conversion.rs
// Algorithm 19 BitUnpack(v,a,b) on page 31                 --> conversion.rs
// Algorithm 20 HintBitPack(h) on page 32                   --> conversion.rs
// Algorithm 21 HintBitUnpack(y) on page 32                 --> conversion.rs
// Algorithm 22 pkEncode(ρ,t1) on page 33                   --> encodings.rs
// Algorithm 23 pkDecode(pk) on page 33                     --> encodings.rs
// Algorithm 24 skEncode(ρ,K,tr,s1,s2,t0) on page 34        --> encodings.rs
// Algorithm 25 skDecode(sk) on page 34                     --> encodings.rs
// Algorithm 26 sigEncode(c˜,z,h) on page 35                --> encodings.rs
// Algorithm 27 sigDecode(σ) on page 35                     --> encodings.rs
// Algorithm 28 w1Encode(w1) on page 35                     --> encodings.rs
// Algorithm 29 SampleInBall(ρ) on page 36                  --> hashing.rs
// Algorithm 30 RejNTTPoly(ρ) on page 37                    --> hashing.rs
// Algorithm 31 RejBoundedPoly(ρ) on page 37                --> hashing.rs
// Algorithm 32 ExpandA(ρ) on page 38                       --> hashing.rs
// Algorithm 33 ExpandS(ρ) on page 38                       --> hashing.rs
// Algorithm 34 ExpandMask(ρ,µ) on page 38                  --> hashing.rs
// Algorithm 35 Power2Round(r) on page 40                   --> high_low.rs
// Algorithm 36 Decompose(r) on page 40                     --> high_low.rs
// Algorithm 37 HighBits(r) on page 40                      --> high_low.rs
// Algorithm 38 LowBits(r) on page 41                       --> high_low.rs
// Algorithm 39 MakeHint(z,r) on page 41                    --> high_low.rs
// Algorithm 40 UseHint(h,r) on page 41                     --> high_low.rs
// Algorithm 41 NTT(w) on page 43                           --> ntt.rs
// Algorithm 42 NTT−1(wˆ) on page 44                        --> ntt.rs
// Algorithm 43 BitRev8(m) on page 44                       --> not needed to to zeta table
// Algorithm 44 AddNTT(a,b)̂ on page 45                      --> helpers.rs within 46:AddVectorNTT
// Algorithm 45 MultiplyNTT(a,b)̂ on page 45                 --> helpers.rs
// Algorithm 46 AddVectorNTT(v,w) on page 45                --> helpers.rs
// Algorithm 47 ScalarVectorNTT(c,v)̂ on page 46             --> not implemented standalone
// Algorithm 48 MatrixVectorNTT(M,v) on page 46             --> not implemented standalone
// Algorithm 49 MontgomeryReduce(a) on page 50              --> helpers.rs
// Types are in types.rs, traits are in traits.rs...

use rand_core::CryptoRngCore;

mod conversion;
mod encodings;
mod hashing;
mod helpers;
mod high_low;
mod ml_dsa;
mod ntt;
mod traits;
mod types;

use traits::ParameterSet;
pub use traits::{KeyGen, SerDes, Signer, Verifier};
use types::Ph;

// Applies across all security parameter sets
pub(crate) const Q: i32 = 8_380_417; // 2^23 - 2^13 + 1 = 0x7FE001; page 15 table 1 first row
pub(crate) const D: u32 = 13; // See page 15 table 1 third row

// This common functionality is injected into each security parameter set, and is
// largely a lightweight wrapper into the ml_dsa functions.
macro_rules! functionality {
    () => {
        // type
        type PrivateKey = types::PrivateKey<{ Self::K }, { Self::L }>;
        type PublicKey = types::PublicKey<{ Self::K }, { Self::L }>;
        type Signature = [u8; Self::SIG_LEN];
        type PrivateKeyEncoded = [u8; Self::SK_LEN];
        type PublicKeyEncoded = [u8; Self::PK_LEN];
        //fn
        fn key_gen(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
            ml_dsa::key_gen::<
                { Self::CTEST },
                { Self::K },
                { Self::L },
                { Self::PK_LEN },
                { Self::SK_LEN },
            >(rng, Self::ETA)
        }
        fn key_gen_internal(xi: &[u8; 32]) -> (Self::PublicKey, Self::PrivateKey) {
            ml_dsa::key_gen_internal::<
                { Self::CTEST },
                { Self::K },
                { Self::L },
                { Self::PK_LEN },
                { Self::SK_LEN },
            >(Self::ETA, xi)
        }
        fn sign_internal(
            esk: &Self::PrivateKey,
            message: &[u8],
            ctx: &[u8],
            oid: &[u8],
            phm: &[u8],
            rnd: [u8; 32],
            nist: bool,
        ) -> Self::Signature {
            ml_dsa::sign_internal::<
                { Self::CTEST },
                { Self::K },
                { Self::L },
                { Self::LAMBDA_DIV4 },
                { Self::SIG_LEN },
                { Self::SK_LEN },
                { Self::W1_LEN },
            >(
                Self::BETA,
                Self::GAMMA1,
                Self::GAMMA2,
                Self::OMEGA,
                Self::TAU,
                esk,
                message,
                ctx,
                oid,
                phm,
                rnd,
                nist,
            )
        }
        fn verify_internal(
            epk: &Self::PublicKey,
            m: &[u8],
            sig: &Self::Signature,
            ctx: &[u8],
            oid: &[u8],
            phm: &[u8],
            nist: bool,
        ) -> bool {
            ml_dsa::verify_internal::<
                { Self::CTEST },
                { Self::K },
                { Self::L },
                { Self::LAMBDA_DIV4 },
                { Self::PK_LEN },
                { Self::SIG_LEN },
                { Self::W1_LEN },
            >(
                Self::BETA,
                Self::GAMMA1,
                Self::GAMMA2,
                Self::OMEGA,
                Self::TAU,
                epk,
                m,
                sig,
                ctx,
                oid,
                phm,
                nist,
            )
        }
        fn expand_private(sk: &Self::PrivateKeyEncoded) -> Result<Self::PrivateKey, &'static str> {
            ml_dsa::expand_private::<{ Self::K }, { Self::L }, { Self::SK_LEN }>(Self::ETA, sk)
        }
        fn expand_public(pk: &Self::PublicKeyEncoded) -> Result<Self::PublicKey, &'static str> {
            ml_dsa::expand_public::<{ Self::K }, { Self::L }, { Self::PK_LEN }>(pk)
        }
        fn encode_private(sk: &Self::PrivateKey) -> Self::PrivateKeyEncoded {
            ml_dsa::encode_private::<{ Self::K }, { Self::L }, { Self::SK_LEN }, { Self::ETA }>(sk)
        }
        fn encode_public(pk: &Self::PublicKey) -> Self::PublicKeyEncoded {
            ml_dsa::encode_public::<{ Self::K }, { Self::L }, { Self::PK_LEN }>(pk)
        }
        fn private_to_public_key(sk: &Self::PrivateKey) -> Self::PublicKey {
            ml_dsa::private_to_public_key::<{ Self::K }, { Self::L }>(sk)
        }
        fn public_try_from(v: &[u8]) -> Result<Self::PublicKey, &'static str> {
            let pk: Self::PublicKeyEncoded = v.try_into().map_err(|_| "Invalid length")?;
            Self::expand_public(&pk)
        }
        fn private_try_from(v: &[u8]) -> Result<Self::PrivateKey, &'static str> {
            let sk: Self::PrivateKeyEncoded = v.try_into().map_err(|_| "Invalid length")?;
            Self::expand_private(&sk)
        }
    };
}

/// The `MlDsa44ParameterSet` struct defines the parameters for the ML-DSA-44 security level.
#[derive(Clone, Debug)]
pub struct MlDsa44ParameterSet;

impl ParameterSet for MlDsa44ParameterSet {
    // const
    const TAU: i32 = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: i32 = 1 << 17;
    const GAMMA2: i32 = (Q - 1) / 88;
    const K: usize = 4;
    const L: usize = 4;
    const ETA: i32 = 2;
    const OMEGA: i32 = 80;
    const SK_LEN: usize = 2560;
    const PK_LEN: usize = 1312;
    const SIG_LEN: usize = 2420;

    functionality!();
}

/// The `MlDsa65ParameterSet` struct defines the parameters for the ML-DSA-65 security level.
#[derive(Clone, Debug)]
pub struct MlDsa65ParameterSet;

impl ParameterSet for MlDsa65ParameterSet {
    // const
    const TAU: i32 = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (Q - 1) / 32;
    const K: usize = 6;
    const L: usize = 5;
    const ETA: i32 = 4;
    const OMEGA: i32 = 55;
    const SK_LEN: usize = 4032;
    const PK_LEN: usize = 1952;
    const SIG_LEN: usize = 3309;

    functionality!();
}

/// The `MlDsa87ParameterSet` struct defines the parameters for the ML-DSA-87 security level.
#[derive(Clone, Debug)]
pub struct MlDsa87ParameterSet;

impl ParameterSet for MlDsa87ParameterSet {
    // const
    const TAU: i32 = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (Q - 1) / 32;
    const K: usize = 8;
    const L: usize = 7;
    const ETA: i32 = 2;
    const OMEGA: i32 = 75;
    const SK_LEN: usize = 4896;
    const PK_LEN: usize = 2592;
    const SIG_LEN: usize = 4627;

    functionality!();
}

/// The `PublicKey` struct is a container for a public key specific to a given `ParameterSet`.
#[derive(Clone, Debug)]
pub struct PublicKey<P: ParameterSet> {
    pub(crate) pk: P::PublicKey,
}
/// The `PrivateKey` struct is a container for a private key specific to a given `ParameterSet`.
#[derive(Clone, Debug)]
pub struct PrivateKey<P: ParameterSet> {
    pub(crate) sk: P::PrivateKey,
}

/// The `MlDsa` struct is a container for ML-DSA operations parameterized by a specific
/// `ParameterSet`.
#[derive(Debug)]
pub struct MlDsa<P: ParameterSet> {
    _params: P::Signature,
}

// for test
impl<P: ParameterSet> MlDsa<P> {
    // for test
    #[deprecated = "Temporary function to allow application of internal nist vectors; will be removed"]
    /// As of Oct 30 2024, the NIST test vectors are applied to the **internal** functions rather than
    /// the external API.
    ///
    /// The primary difference pertains to the prepending of domain, context, OID and
    /// hash information to the message in the `sign_finish()` and `verify_finish()` functions (follow
    /// the last `nist=true` function argument). This is expected to change such that the full API can
    /// be robustly tested - when this happens, this function will no longer be needed.
    /// # Errors
    /// Propagate errors from the `sign_finish()` function (for failing RNG).
    pub fn _internal_sign(
        sk: &PrivateKey<P>,
        message: &[u8],
        ctx: &[u8],
        rnd: [u8; 32],
    ) -> Result<P::Signature, &'static str> {
        helpers::ensure!(ctx.len() < 256, "_internal_sign: ctx too long");
        let sig = P::sign_internal(&sk.sk, message, ctx, &[], &[], rnd, true);
        Ok(sig)
    }
    #[deprecated = "Temporary function to allow application of internal nist vectors; will be removed"]
    #[must_use]
    /// As of Oct 30 2024, the NIST test vectors are applied to the **internal** functions rather than
    /// the external API.
    ///
    /// The primary difference pertains to the prepending of domain, context, OID and
    /// hash information to the message in the `sign_finish()` and `verify_finish()` functions (follow
    /// the last `nist=true` function argument). This is expected to change such that the full API can
    /// be robustly tested - when this happens, this function will no longer be needed.
    pub fn _internal_verify(
        pk: &PublicKey<P>,
        message: &[u8],
        sig: &P::Signature,
        ctx: &[u8],
    ) -> bool {
        if ctx.len() > 255 {
            return false;
        };
        P::verify_internal(&pk.pk, message, sig, ctx, &[], &[], true)
    }
}

// Implement the KeyGen traits for MlDsa
impl<P: ParameterSet> KeyGen for MlDsa<P> {
    type PublicKey = PublicKey<P>;
    type PrivateKey = PrivateKey<P>;

    fn try_keygen_with_rng(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
        let (pk, sk) = P::key_gen(rng)?;
        Ok((PublicKey { pk }, PrivateKey { sk }))
    }

    fn keygen_from_seed(xi: &[u8; 32]) -> (Self::PublicKey, Self::PrivateKey) {
        let (pk, sk) = P::key_gen_internal(xi);
        (PublicKey { pk }, PrivateKey { sk })
    }
}

// Implement the Signer traits for PrivateKey
impl<P: ParameterSet> Signer for PrivateKey<P> {
    type Signature = P::Signature;
    type PublicKey = PublicKey<P>;

    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        message: &[u8],
        ctx: &[u8],
    ) -> Result<Self::Signature, &'static str> {
        // 1: if |ctx| > 255 then
        // 2:   return ⊥    ▷ return an error indication if the context string is too long
        // 3: end if
        helpers::ensure!(ctx.len() < 256, "ML-DSA.Sign: ctx too long");

        // 4:  (blank line in spec)

        // 5: rnd ← 𝔹^{32}     ▷ for the optional deterministic variant, substitute rnd ← {0}^32
        // 6: if rnd = NULL then
        // 7:   return ⊥    ▷ return an error indication if random bit generation failed
        // 8: end if
        let mut rnd = [0u8; 32];
        rng.try_fill_bytes(&mut rnd)
            .map_err(|_| "ML-DSA.Sign: random number generator failed")?;

        // 9:  (blank line in spec)

        // Note: step 10 is done within sign_internal() and 'below'
        // 10: 𝑀 ′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        // 11: 𝜎 ← ML-DSA.Sign_internal(𝑠𝑘, 𝑀 ′ , 𝑟𝑛𝑑)
        let sig = P::sign_internal(&self.sk, message, ctx, &[], &[], rnd, false);

        // 12: return 𝜎
        Ok(sig)
    }

    fn try_hash_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        message: &[u8],
        ctx: &[u8],
        ph: &Ph,
    ) -> Result<Self::Signature, &'static str> {
        // 1: if |ctx| > 255 then
        // 2:   return ⊥    ▷ return an error indication if the context string is too long
        // 3: end if
        helpers::ensure!(ctx.len() < 256, "ML-DSA.HashSign: ctx too long");

        // 4:  (blank line in spec)

        // 5: rnd ← 𝔹^{32}     ▷ for the optional deterministic variant, substitute rnd ← {0}^32
        // 6: if rnd = NULL then
        // 7:   return ⊥    ▷ return an error indication if random bit generation failed
        // 8: end if
        let mut rnd = [0u8; 32];
        rng.try_fill_bytes(&mut rnd)
            .map_err(|_| "ML-DSA.HashSign: random number generator failed")?;

        // 9:  (blank line in spec)

        // Note: steps 10-22 are performed within `hash_message()` below
        let mut phm = [0u8; 64]; // hashers don't all play well with each other
        let (oid, phm_len) = hashing::hash_message(message, ph, &mut phm);

        // Note: step 23 is performed within `sign_internal()` and below.
        // 23: 𝑀 ′ ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀 )
        // 24: 𝜎 ← ML-DSA.Sign_internal(𝑠𝑘, 𝑀 ′ , 𝑟𝑛𝑑)
        let sig = P::sign_internal(&self.sk, message, ctx, &oid, &phm[0..phm_len], rnd, false);

        // 25: return 𝜎
        Ok(sig)
    }

    fn get_public_key(&self) -> Self::PublicKey {
        let pk = P::private_to_public_key(&self.sk);
        PublicKey { pk }
    }
}

// Implement the Verifier traits for PublicKey
impl<P: ParameterSet> Verifier for PublicKey<P> {
    type Signature = P::Signature;

    fn verify(&self, message: &[u8], signature: &Self::Signature, ctx: &[u8]) -> bool {
        // 1: if |ctx| > 255 then
        // 2:   return false    ▷ return an error indication if the context string is too long
        // 3: end if
        if ctx.len() > 255 {
            return false;
        }

        // 4:  (blank line in spec)

        // Note: step 5 is performed within `verify_internal()` and below.
        // 5: 𝑀′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|ctx|, 1) ∥ ctx) ∥ 𝑀
        // 6: return ML-DSA.Verify_internal(pk, 𝑀′, 𝜎)
        P::verify_internal(&self.pk, message, signature, ctx, &[], &[], false)
    }
    fn hash_verify(&self, message: &[u8], sig: &Self::Signature, ctx: &[u8], ph: &Ph) -> bool {
        // 1: if |ctx| > 255 then
        // 2:   return false    ▷ return an error indication if the context string is too long
        // 3: end if
        if ctx.len() > 255 {
            return false;
        }

        // 4:  (blank line in spec)

        // Note: steps 5-17 are performed within `hash_message()` below
        let mut phm = [0u8; 64]; // hashers don't all play well with each other
        let (oid, phm_len) = hashing::hash_message(message, ph, &mut phm);

        // Note: step 18 is performed within `verify_internal()` and below.
        // 18: 𝑀′ ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|ctx|, 1) ∥ ctx ∥ OID ∥ PH𝑀)
        // 19: return ML-DSA.Verify_internal(pk, 𝑀′, 𝜎)
        P::verify_internal(&self.pk, message, sig, ctx, &oid, &phm[0..phm_len], false)
    }
}

// Implement serialization/deserialization for PublicKey and PrivateKey
impl<P: ParameterSet> SerDes for PublicKey<P> {
    type ByteArray = P::PublicKeyEncoded;

    fn into_bytes(self) -> Self::ByteArray {
        P::encode_public(&self.pk)
    }

    fn try_from_bytes(ba: &Self::ByteArray) -> Result<Self, &'static str> {
        let pk = P::expand_public(ba)?;
        Ok(PublicKey { pk })
    }
}

impl<P: ParameterSet> SerDes for PrivateKey<P> {
    type ByteArray = P::PrivateKeyEncoded;

    fn into_bytes(self) -> Self::ByteArray {
        P::encode_private(&self.sk)
    }

    fn try_from_bytes(ba: &Self::ByteArray) -> Result<Self, &'static str> {
        let sk = P::expand_private(ba)?;
        Ok(PrivateKey { sk })
    }
}

// Implement TryFrom<&[u8]> for PublicKey and PrivateKey
impl<P: ParameterSet> TryFrom<&[u8]> for PublicKey<P> {
    type Error = &'static str;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        let pk = P::public_try_from(v)?;
        Ok(PublicKey { pk })
    }
}

impl<P: ParameterSet> TryFrom<&[u8]> for PrivateKey<P> {
    type Error = &'static str;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        let sk = P::private_try_from(v)?;
        Ok(PrivateKey { sk })
    }
}

/// Type alias for the ml-dsa-44 security parameter set
pub type MlDsa44 = MlDsa<MlDsa44ParameterSet>;
/// Type alias for the ml-dsa-65 security parameter set
pub type MlDsa65 = MlDsa<MlDsa65ParameterSet>;
/// Type alias for the ml-dsa-87 security parameter set
pub type MlDsa87 = MlDsa<MlDsa87ParameterSet>;

//----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn ml_dsa_44_smoke_test() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let message1 = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let message2 = [7u8, 7, 7, 7, 7, 7, 7, 7];

        for _i in 0..32 {
            let (pk, sk) = MlDsa44::try_keygen_with_rng(&mut rng).unwrap();
            let sig = sk.try_sign_with_rng(&mut rng, &message1, &[]).unwrap();
            assert!(pk.verify(&message1, &sig, &[]));
            assert!(!pk.verify(&message2, &sig, &[]));
            for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
                let sig = sk
                    .try_hash_sign_with_rng(&mut rng, &message1, &[], &ph)
                    .unwrap();
                let v = pk.hash_verify(&message1, &sig, &[], &ph);
                assert!(v);
            }
            assert_eq!(pk.clone().into_bytes(), sk.get_public_key().into_bytes());
        }

        let (pk, sk) = MlDsa44::try_keygen().unwrap();
        let sig = sk.try_sign(&message1, &[]).unwrap();
        assert!(pk.verify(&message1, &sig, &[]));
        assert!(!pk.verify(&message2, &sig, &[]));
        assert!(!pk.verify(&message1, &sig, &[0u8; 257]));
        assert!(sk.try_sign(&message1, &[0u8; 257]).is_err());

        for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
            let sig = sk.try_hash_sign(&message1, &[], &ph).unwrap();
            let v = pk.hash_verify(&message1, &sig, &[], &ph);
            assert!(v);
        }
        assert_eq!(pk.clone().into_bytes(), sk.get_public_key().into_bytes());

        let (pk, sk) = MlDsa44::keygen_from_seed(&[0x11u8; 32]);
        let sig = sk.try_sign_with_seed(&[12u8; 32], &message1, &[]).unwrap();
        assert!(pk.verify(&message1, &sig, &[]));
        let sig = sk
            .try_hash_sign_with_seed(&[34u8; 32], &message1, &[], &Ph::SHA256)
            .unwrap();
        assert!(pk.hash_verify(&message1, &sig, &[], &Ph::SHA256));

        let pk_bytes = pk.into_bytes();
        assert!(pk_bytes.len() == 1312);
        assert_eq!(pk_bytes[0], 197);
    }

    #[test]
    fn ml_dsa_65_smoke_test() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let message1 = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let message2 = [7u8, 7, 7, 7, 7, 7, 7, 7];

        for _i in 0..32 {
            let (pk, sk) = MlDsa65::try_keygen_with_rng(&mut rng).unwrap();
            let sig = sk.try_sign_with_rng(&mut rng, &message1, &[]).unwrap();
            assert!(pk.verify(&message1, &sig, &[]));
            assert!(!pk.verify(&message2, &sig, &[]));
            for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
                let sig = sk
                    .try_hash_sign_with_rng(&mut rng, &message1, &[], &ph)
                    .unwrap();
                let v = pk.hash_verify(&message1, &sig, &[], &ph);
                assert!(v);
            }
            assert_eq!(pk.clone().into_bytes(), sk.get_public_key().into_bytes());
        }

        let (pk, sk) = MlDsa65::try_keygen().unwrap();
        let sig = sk.try_sign(&message1, &[]).unwrap();
        assert!(pk.verify(&message1, &sig, &[]));
        assert!(!pk.verify(&message2, &sig, &[]));
        assert!(!pk.verify(&message1, &sig, &[0u8; 257]));
        assert!(sk.try_sign(&message1, &[0u8; 257]).is_err());

        for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
            let sig = sk.try_hash_sign(&message1, &[], &ph).unwrap();
            let v = pk.hash_verify(&message1, &sig, &[], &ph);
            assert!(v);
        }
        assert_eq!(pk.clone().into_bytes(), sk.get_public_key().into_bytes());

        let (pk, sk) = MlDsa65::keygen_from_seed(&[0x11u8; 32]);
        let sig = sk.try_sign_with_seed(&[12u8; 32], &message1, &[]).unwrap();
        assert!(pk.verify(&message1, &sig, &[]));
        let sig = sk
            .try_hash_sign_with_seed(&[34u8; 32], &message1, &[], &Ph::SHA256)
            .unwrap();
        assert!(pk.hash_verify(&message1, &sig, &[], &Ph::SHA256));

        let pk_bytes = pk.into_bytes();
        assert!(pk_bytes.len() == 1952);
        assert_eq!(pk_bytes[0], 177);
    }

    #[test]
    fn ml_dsa_87_smoke_test() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        let message1 = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let message2 = [7u8, 7, 7, 7, 7, 7, 7, 7];

        for _i in 0..32 {
            let (pk, sk) = MlDsa87::try_keygen_with_rng(&mut rng).unwrap();
            let sig = sk.try_sign_with_rng(&mut rng, &message1, &[]).unwrap();
            assert!(pk.verify(&message1, &sig, &[]));
            assert!(!pk.verify(&message2, &sig, &[]));
            for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
                let sig = sk
                    .try_hash_sign_with_rng(&mut rng, &message1, &[], &ph)
                    .unwrap();
                let v = pk.hash_verify(&message1, &sig, &[], &ph);
                assert!(v);
            }
            assert_eq!(pk.clone().into_bytes(), sk.get_public_key().into_bytes());
        }

        let (pk, sk) = MlDsa87::try_keygen().unwrap();
        let sig = sk.try_sign(&message1, &[]).unwrap();
        assert!(pk.verify(&message1, &sig, &[]));
        assert!(!pk.verify(&message2, &sig, &[]));
        assert!(!pk.verify(&message1, &sig, &[0u8; 257]));
        assert!(sk.try_sign(&message1, &[0u8; 257]).is_err());

        for ph in [Ph::SHA256, Ph::SHA512, Ph::SHAKE128] {
            let sig = sk.try_hash_sign(&message1, &[], &ph).unwrap();
            let v = pk.hash_verify(&message1, &sig, &[], &ph);
            assert!(v);
        }
        assert_eq!(pk.clone().into_bytes(), sk.get_public_key().into_bytes());

        let (pk, sk) = MlDsa87::keygen_from_seed(&[0x11u8; 32]);
        let sig = sk.try_sign_with_seed(&[12u8; 32], &message1, &[]).unwrap();
        assert!(pk.verify(&message1, &sig, &[]));
        let sig = sk
            .try_hash_sign_with_seed(&[34u8; 32], &message1, &[], &Ph::SHA256)
            .unwrap();
        assert!(pk.hash_verify(&message1, &sig, &[], &Ph::SHA256));

        let pk_bytes = pk.into_bytes();
        assert!(pk_bytes.len() == 2592);
        assert_eq!(pk_bytes[0], 16);
    }
}
