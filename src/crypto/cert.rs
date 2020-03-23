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

use crate::crypto::{
    validate_signature, DeviceCert, Fingerprint, IdentCert, Public, Secret, SignatureBytes,
    Trusted, Untrusted,
};


/// Cert trait which all Certificate variants must implement.
pub trait Cert: AsRef<[u8]> {
    /// Serialize the certificate into ASN.1. The concrete format
    /// is up to the variant implementation. Each implementation must provide
    /// to re-read the serialized data back.
    fn serialize(&self, stream: &mut dyn Write);

    /// Returns the fingerprint of the issuer certificate.
    /// If the certificate is self-signed, the issuer fingerprint is
    /// the fingerprint from the certificate itself.
    fn issuer_fingerprint(&self) -> Fingerprint;

    /// Returns the raw bytes of the public signing key
    fn signing_public_key(&self) -> &[u8];

    /// Validate the certificate againts a specific issuer certificate.
    /// The issuer can be found by using `issuer_fingerprint`, then by
    /// a lookup into a managed trusted keystore.
    fn is_valid(&self, issuer_cert: &dyn Cert) -> bool;

    /// Returns the fingerprint from the certificate.
    /// The fingerprint is determined by using a SHA256 digest over
    /// the raw certificate bytes.
    fn fingerprint(&self) -> Fingerprint {
        let raw = self.as_ref();
        let d = digest::digest(&digest::SHA256, raw);
        let mut inner: [u8; 32] = [0; 32];
        inner.copy_from_slice(&d.as_ref()[0..32]);
        Fingerprint { inner }
    }
}
