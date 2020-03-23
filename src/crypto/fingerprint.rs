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

/// Stores a fingerprint calculated by a SHA256 digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    // SHA-256 checksum over raw certificate data
    pub inner: [u8; 32],
}

impl<T: AsRef<[u8]>> From<&T> for Fingerprint {
    fn from(bytes: &T) -> Self {
        let d = digest::digest(&digest::SHA256, bytes.as_ref());
        let mut inner: [u8; 32] = [0; 32];
        inner.copy_from_slice(&d.as_ref()[0..32]);
        Fingerprint { inner }
    }
}

impl Fingerprint {}

impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let b32 = data_encoding::BASE32.encode(&self.inner).replace("=", "");

        for i in 0..4 {
            if i > 0 {
                formatter.write_str("-")?;
            }
            let group = String::from(&b32[(i * 13)..(i * 13) + 13]);
            formatter.write_str(&group[0..7])?;
            formatter.write_str("-")?;
            formatter.write_str(&group[7..13])?;
            formatter.write_str("X")?; // TODO LUHN ALGO
        }
        Ok(())
    }
}
