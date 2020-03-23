// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (C) 2020 Daniel Vogelbacher
 * Written by: Daniel Vogelbacher <daniel@chaospixel.com>
 */

pub mod alpha;

pub mod cert;
pub mod fingerprint;
pub mod key;
pub mod sign;

pub use cert::Cert;
pub use fingerprint::Fingerprint;
pub use key::{Encrypted, Public, Secret};
pub use sign::{validate_signature, SignatureBytes};

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

use log;
use std::error::Error as StdError;
use std::fs;
use std::path::PathBuf;
//use failure::Error;
use failure::Fail;

/// Error type for this module
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Internal error: {:?}", _0)]
    General(String),
    #[fail(display = "Not valid: {:?}", _0)]
    NotValid(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Trusted;
pub struct Untrusted;

/// Stores a certificate used for Identity.
pub struct IdentCert<T> {
    inner: Box<dyn Cert>,
    phantom: std::marker::PhantomData<T>,
}

/// Implementation for untrusted IdentCert
impl IdentCert<Untrusted> {
    /// Constructs a untrusted IdentCert from a given Cert.
    pub fn new(cert: Box<dyn Cert>) -> Self {
        IdentCert::<Untrusted> {
            inner: cert,
            phantom: std::marker::PhantomData,
        }
    }

    /// Converts the untrusted certificate into a trusted one.
    /// For IdentCert, there are nor further checks because IdentCerts
    /// are the root certificates - you simply trust them or not.
    pub fn into_trusted(self) -> IdentCert<Trusted> {
        IdentCert::<Trusted> {
            inner: self.inner,
            phantom: std::marker::PhantomData,
        }
    }
}

impl std::ops::Deref for IdentCert<Trusted> {
    type Target = dyn Cert;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl std::ops::Deref for IdentCert<Untrusted> {
    type Target = dyn Cert;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

/// Stores a certificate used for Devices.
pub struct DeviceCert<T> {
    inner: Box<dyn Cert>,
    phantom: std::marker::PhantomData<T>,
}

/// Implementation for untrusted DeviceCert
impl DeviceCert<Untrusted> {
    /// Constructs a untrusted IdentCert from a given Cert.
    pub fn new(cert: Box<dyn Cert>) -> Self {
        DeviceCert::<Untrusted> {
            inner: cert,
            phantom: std::marker::PhantomData,
        }
    }

    /// Converts the untrusted certificate into a trusted one.
    /// For DeviceCert, this must validate against a issuer certificate
    /// which is trusted.
    pub fn into_trusted(self, issuer_cert: &dyn Cert) -> DeviceCert<Trusted> {
        if self.is_valid(issuer_cert) {
            DeviceCert::<Trusted> {
                inner: self.inner,
                phantom: std::marker::PhantomData,
            }
        } else {
            // TODO
            unimplemented!();
        }
    }
}

impl std::ops::Deref for DeviceCert<Trusted> {
    type Target = dyn Cert;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl std::ops::Deref for DeviceCert<Untrusted> {
    type Target = dyn Cert;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::General(format!("{}", err))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Error {
        Error::General(format!("{}", err))
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Error {
        Error::General(format!("{}", err))
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::General(format!("{}", err))
    }
}

impl From<uuid::parser::ParseError> for Error {
    fn from(err: uuid::parser::ParseError) -> Self {
        Error::General(format!("{}", err))
    }
}
