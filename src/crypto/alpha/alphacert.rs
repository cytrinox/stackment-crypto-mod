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

use super::alphasecret::AlphaSecret;

use crate::crypto::{
    validate_signature, Cert, DeviceCert, Fingerprint, IdentCert, Public, Secret, Trusted,
    Untrusted,
};

/// Alpha certificate
/// Contains the raw certificate bytes and parsing results
#[derive(Clone)]
pub struct AlphaCert {
    raw: Vec<u8>,
    signature_pubkey: Vec<u8>,
    encryption_pubkey: Vec<u8>,
    issuer: Fingerprint,
}

impl AsRef<[u8]> for AlphaCert {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl AlphaCert {
    /// Constructs a new AlphaCert from the given secret and issuer_secret.
    /// If the `issuer` is None, this generateds a selfsigned certificate.
    /// TODO: Maybe add purpose flags to the certificate
    pub fn new(
        secret: &AlphaSecret,
        issuer_secret: &AlphaSecret,
        issuer: Option<&AlphaCert>,
    ) -> Self {
        // TODO: fail if issuer is None and secret and issuer_secret differ!
        let ed25519_pubkey = secret.public_key().signing_public_key(); //secret.ed25519_keypair.public_key().as_ref();
        let x25519_pubkey = secret.public_key().encryption_public_key(); //&secret.x25519_keypair.public;

        let cert_subject_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // subject sequence, to be signed
                writer.next().write_generalized_time(
                    // creation time
                    &GeneralizedTime::from_datetime(&Utc::now()),
                );
                writer.next().write_bytes(ed25519_pubkey); // public key
                writer.next().write_bytes(x25519_pubkey); // public key
                if let Some(issuer) = issuer {
                    writer.next().write_bytes(&issuer.fingerprint().inner); // issuer fingerprint
                }
            });
        });
        let signature = issuer_secret.sign(&cert_subject_der);
        let cert_signed_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_i64(1); // Version
                writer.next().write_der(&cert_subject_der); // cert data, subject sequence
                writer.next().write_bytes(signature.as_ref()); // signature for cert
            });
        });

        let fingerprint = if let Some(issuer) = issuer {
            issuer.issuer_fingerprint()
        } else {
            Fingerprint::from(cert_signed_der.as_slice())
        };

        Self {
            raw: cert_signed_der,
            signature_pubkey: Vec::from(ed25519_pubkey),
            encryption_pubkey: Vec::from(x25519_pubkey),
            issuer: fingerprint,
        }
    }


    /*
    pub fn build_cert_and_sign_dev(
        secret: &AlphaSecret,
        issuer: &AlphaSecret,
        issuer_cert: &dyn Cert,
    ) -> Vec<u8> {
        let ed25519_pubkey = secret.ed25519_keypair.public_key().as_ref();
        let x25519_pubkey = &secret.x25519_keypair.public;
        let cert_unsigned_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // subject sequence, to be signed
                writer.next().write_generalized_time(
                    // creation time
                    &GeneralizedTime::from_datetime(&Utc::now()),
                );
                writer.next().write_bytes(ed25519_pubkey); // public key for device
                writer.next().write_bytes(x25519_pubkey); // public key for device
                writer.next().write_bytes(&issuer_cert.fingerprint().inner); // issuer
            });
        });
        let signature = issuer.sign(&cert_unsigned_der);
        let cert_signed_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_i64(1); // Version
                writer.next().write_der(&cert_unsigned_der); // cert data, subject sequence
                writer.next().write_bytes(signature.as_ref()); // signature for cert
            });
        });

        cert_signed_der
    }


    pub fn build_cert_and_sign_final(
        secret: &AlphaSecret,
        issuer_secret: &AlphaSecret,
        issuer_cert: Option<&AlphaCert>,
    ) -> Vec<u8> {
        let ed25519_pubkey = secret.ed25519_keypair.public_key().as_ref();
        let x25519_pubkey = &secret.x25519_keypair.public;

        let cert_unsigned_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // subject sequence, to be signed
                writer.next().write_generalized_time(
                    // creation time
                    &GeneralizedTime::from_datetime(&Utc::now()),
                );
                writer.next().write_bytes(ed25519_pubkey); // public key for device
                writer.next().write_bytes(x25519_pubkey); // public key for device
                writer.next().write_bytes(&issuer_cert.unwrap().issuer_fingerprint().unwrap().inner); // issuer
            });
        });
        let signature = issuer_secret.sign(&cert_unsigned_der);
        let cert_signed_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_i64(1); // Version
                writer.next().write_der(&cert_unsigned_der); // cert data, subject sequence
                writer.next().write_bytes(signature.as_ref()); // signature for cert
            });
        });

        cert_signed_der
    }
    */

    /*
    pub fn into_dev_cert(self) -> UntrustedDevCert {
        UntrustedDevCert {
            inner: Untrusted(Box::from(self)),
        }
    }
    */

    /*
    fn verify_signature(&self, bytes: &dyn AsRef<[u8]>, sig: &SignatureBytes) {
        panic!("tofo")
    }
    fn encrypt(&self, plain_bytes: &dyn AsRef<[u8]>) -> Vec<u8> {
        panic!("tofo")
    }
    */
}

impl From<AlphaCert> for IdentCert<Untrusted> {
    fn from(alphacert: AlphaCert) -> Self {
        IdentCert::<Untrusted> {
            inner: Box::new(alphacert),
            phantom: std::marker::PhantomData,
        }
    }
}

impl From<AlphaCert> for DeviceCert<Untrusted> {
    fn from(alphacert: AlphaCert) -> Self {
        DeviceCert::<Untrusted> {
            inner: Box::new(alphacert),
            phantom: std::marker::PhantomData,
        }
    }
}

impl From<&[u8]> for AlphaCert {
    fn from(bytes: &[u8]) -> Self {
        let asn = yasna::parse_der(&bytes, |reader| {
            reader.read_sequence(|reader| {
                let _version = reader.next().read_i64()?;

                let cert_data = reader.next().read_der()?;
                let cert_signature = reader.next().read_bytes()?;

                yasna::parse_der(&cert_data, |reader| {
                    reader.read_sequence(|reader| {
                        let cert_date = reader.next().read_generalized_time()?;
                        let sign_pubkey = reader.next().read_bytes()?;
                        let crypt_pubkey = reader.next().read_bytes()?;
                        // TODO: check for optional issuer
                        unimplemented!();
                        let issuer = reader.next().read_bytes()?;

                        let mut inner: [u8; 32] = [0; 32];

                        inner.copy_from_slice(&issuer[0..32]);

                        Ok(Self {
                            raw: bytes.to_owned(),
                            signature_pubkey: sign_pubkey,
                            encryption_pubkey: crypt_pubkey,
                            issuer: Fingerprint { inner },
                        })
                    })
                })
            })
        });
        asn.unwrap()
    }
}

impl<Stream: Read> From<&mut Stream> for AlphaCert {
    fn from(stream: &mut Stream) -> Self {
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        Self::from(raw.as_slice())
    }
}

impl Cert for AlphaCert {
    fn issuer_fingerprint(&self) -> Fingerprint {
        self.issuer
        //Some(self.fingerprint())
    }

    fn serialize(&self, stream: &mut dyn Write) {
        stream.write_all(&self.raw).unwrap()
    }

    fn signing_public_key(&self) -> &[u8] {
        &self.signature_pubkey
    }

    fn is_valid(&self, issuer_cert: &dyn Cert) -> bool {
        let asn = yasna::parse_der(&self.raw, |reader| {
            reader.read_sequence(|reader| {
                let _version = reader.next().read_i64()?;

                let cert_data = reader.next().read_der()?;
                let cert_signature = reader.next().read_bytes()?;

                Ok((cert_data, cert_signature))
            })
        });
        let (cert_data, cert_signature) = asn.expect("Invalid ASN1");
        self.issuer_fingerprint() == issuer_cert.fingerprint()
            && validate_signature(
                issuer_cert.signing_public_key(),
                &cert_data,
                &cert_signature,
            )
            .is_ok()
    }
}
