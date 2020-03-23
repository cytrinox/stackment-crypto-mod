// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (C) 2020 Daniel Vogelbacher
 * Written by: Daniel Vogelbacher <daniel@chaospixel.com>
 */

mod alphacert;
mod alphasecret;

pub use alphacert::AlphaCert;
pub use alphasecret::AlphaSecret;
pub use alphasecret::AlphaPublic;


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::*;

    #[test]
    fn sign_and_verify() {
        let isec = AlphaSecret::new();
        let data = vec![0x34, 0x84, 0x23, 0x98, 0xA2];
        let sig = isec.sign(&data);
        assert_eq!(isec.public_key().verify(&data, &sig), true);
        let data = vec![0x01, 0x02, 0x03];
        assert_eq!(isec.public_key().verify(&data, &sig), false);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let isec = AlphaSecret::new();
        let plain = vec![0x34, 0x84, 0x23, 0x98, 0xA2];
        let crypted = isec.encrypt(&plain, isec.public_key());
        assert_eq!(isec.decrypt(&crypted, isec.public_key()), plain);
    }

    #[test]
    fn save_and_restore_secret() {
        let isec = AlphaSecret::new();
    }

    #[test]
    fn will_it_blend() {
        let isec = AlphaSecret::new();
        let icert = AlphaCert::new(&isec, &isec, None);

        assert_eq!(icert.is_valid(&icert), true);

        let dsec = AlphaSecret::new();
        let dcert = AlphaCert::new(&dsec, &isec, Some(&icert));

        assert_eq!(dcert.is_valid(&icert), true);
    }

    #[test]
    fn will_it_deref() {
        let isec = AlphaSecret::new();
        let icert = AlphaCert::new(&isec, &isec, None);

        let untrusted = IdentCert::from(icert.clone());
        let trusted = untrusted.into_trusted();

        let dsec = AlphaSecret::new();
        let dcert = AlphaCert::new(&dsec, &isec, Some(&icert));

        let dcert = DeviceCert::from(dcert);
        let dcert_trusted = dcert.into_trusted(trusted.deref());
    }
}
