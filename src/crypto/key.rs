// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (C) 2020 Daniel Vogelbacher
 * Written by: Daniel Vogelbacher <daniel@chaospixel.com>
 */

use std::ops::Deref;

use std::fmt;
use std::io::Read;
use std::io::Write;

use chrono::Utc;
use ring::{self, signature::UnparsedPublicKey};
use ring::{
    digest, rand, signature,
    signature::{Ed25519KeyPair, KeyPair, Signature},
};
use snow;
use yasna::{self, models::GeneralizedTime, models::ObjectIdentifier, Tag};

use crate::crypto::{SecretVariant, PublicVariant, CertVariant};


use crate::crypto::SignatureBytes;


/// Trait for public key information
pub trait Public {
    /// Returns the public signing key as raw bytes
    fn signing_public_key(&self) -> &[u8];

    /// Returns the public encryption key as raw bytes
    fn encryption_public_key(&self) -> &[u8];

    /// Verify raw bytes data and a signature against this public key
    fn verify(&self, bytes: &dyn AsRef<[u8]>, signature: &SignatureBytes) -> bool;

    /// Returns the concrete variant reference
    fn as_variant_ref(&self) -> PublicVariant;
}

/// Trait for secret key information
pub trait Secret {
    /// Sign raw bytes and return the signature
    fn sign(&self, bytes: &dyn AsRef<[u8]>) -> SignatureBytes;

    /// Decrypt raw bytes with this key and verify authenticity with `sender_pubkey`.
    fn decrypt(&self, enc_bytes: &Encrypted, sender_pubkey: &dyn Public) -> Vec<u8>;

    /// Serialize the secret key into ASN.1
    /// The concrete format is up to the implementor.
    fn serialize(&self, stream: &mut dyn Write);

    /// Encrypt and sign plaintext bytes
    /// Signing requires the secret key, so this is why encrypt() is not provided
    /// by the Public trait but by the Secret trait.
    fn encrypt(&self, plain_bytes: &dyn AsRef<[u8]>, peer_public: &dyn Public) -> Encrypted;
}


/// Holds the encrypted data and peer's ephemeral public key.
/// TODO: An ephemeral key is specific to the implemention of the alpha variant.
pub struct Encrypted {
    pub ephemeral_pubkey: Vec<u8>,
    pub data: Vec<u8>,
}
