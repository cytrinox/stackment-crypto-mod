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

impl<T: AsRef<[u8]>> From<&T> for SignatureBytes {
    fn from(bytes: &T) -> Self {
        SignatureBytes {
            inner: Vec::from(bytes.as_ref()),
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
pub fn validate_signature<T>(
    public_key: &T,
    message: &T,
    signature: &T,
) -> Result<(), ring::error::Unspecified>
where
    T: AsRef<[u8]> + ?Sized,
{
    let public_key = UnparsedPublicKey::new(&signature::ED25519, &public_key);
    public_key.verify(message.as_ref(), signature.as_ref())
}
