// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (C) 2020 Daniel Vogelbacher
 * Written by: Daniel Vogelbacher <daniel@chaospixel.com>
 */

mod alphacert;
mod alphasecret;

pub use alphacert::AlphaCert;
pub use alphasecret::AlphaSecretKeyring;
pub use alphasecret::AlphaPublicKeyring;


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::*;

    #[test]
    fn sign_and_verify() {
        let isec: Box<dyn SecretKeyring> = Box::from(AlphaSecretKeyring::new());
        let data = vec![0x34, 0x84, 0x23, 0x98, 0xA2];
        let sig = isec.sign(&data);
        assert_eq!(isec.public_keyring().verify(&data, &sig), true);
        let data = vec![0x01, 0x02, 0x03];
        assert_eq!(isec.public_keyring().verify(&data, &sig), false);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let isec: Box<dyn SecretKeyring> = Box::from(AlphaSecretKeyring::new());
        let plain = vec![0x34, 0x84, 0x23, 0x98, 0xA2];
        let crypted = isec.public_keyring().encrypt(&plain, isec.as_ref());
        assert_eq!(isec.decrypt(&crypted, isec.public_keyring()), plain);
    }

    #[test]
    fn save_and_restore_secret() {
        let isec: Box<dyn SecretKeyring> = Box::from(AlphaSecretKeyring::new());
        // TODO
    }

    #[test]
    fn will_it_blend() {
        let isec = AlphaSecretKeyring::new();
        let icert: Box<dyn Cert> = Box::from(AlphaCert::new(&isec, &isec, None));

        assert_eq!(icert.is_valid(icert.as_ref()), true);

        let dsec = AlphaSecretKeyring::new();
        let dcert = AlphaCert::new(&dsec, &isec, Some(icert.as_ref()));

        assert_eq!(dcert.is_valid(icert.as_ref()), true);
    }

    #[test]
    fn will_it_deref() {
        let isec = AlphaSecretKeyring::new();
        let icert = AlphaCert::new(&isec, &isec, None);

        let untrusted = IdentCert::from(icert.clone());
        let trusted = untrusted.into_trusted();

        let dsec = AlphaSecretKeyring::new();
        let dcert = AlphaCert::new(&dsec, &isec, Some(&icert));

        let dcert = DeviceCert::from(dcert);
        let dcert_trusted = dcert.into_trusted(trusted.deref());
    }
}
