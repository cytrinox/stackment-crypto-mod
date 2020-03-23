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

/// Holds the raw signature data
pub struct SignatureBytes {
    inner: Vec<u8>,
}

impl From<&[u8]> for SignatureBytes {
    fn from(bytes: &[u8]) -> Self {
        SignatureBytes {
            inner: bytes.to_owned(),
        }
    }
}

impl SignatureBytes {}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

/// Validate a sigature against a given public key and message.
pub fn validate_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ring::error::Unspecified>
{
    let public_key = UnparsedPublicKey::new(&signature::ED25519, &public_key);
    public_key.verify(message, signature)
}
