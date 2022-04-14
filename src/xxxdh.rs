/// Blake3 is used for debug to ensure that a developer can print the value for debugging
/// but the secret cannot be determined since it's just the hash of the secret and comparing
/// the `blake3::Hash` to another one is done at constant time.
use crate::{prekey_bundle, types::*, PrekeyBundle};
use core::fmt;
use rand::rngs::OsRng;
use std::collections::HashMap;
use tai64::Tai64N;
use x25519_dalek::SharedSecret;

pub struct X3DH {
    secret: X25519Secret,
    static_public_key: X25519PublicKey,
    timestamp: Tai64N,
    signed_prekey: SignedPrekey,
    onetime_prekeys: HashMap<X25519PublicKey, OneTimePreKey>,
    ephemeral_prekeys: HashMap<X25519PublicKey, EphemeralX25519Keypair>,
    shared_secret: blake3::Hash,
}

impl X3DH {
    pub fn new(compute_signature: fn(&[u8]) -> Ed25519Signature) -> Self {
        let timestamp = Tai64N::now();
        let secret = X25519Secret::new(OsRng);
        let signed_prekey = SignedPrekey::new(compute_signature);
        let mut onetime_prekeys: HashMap<X25519PublicKey, OneTimePreKey> = HashMap::default();

        (0..=9u8).for_each(|_| {
            let onetime_prekey = OneTimePreKey::new();
            onetime_prekeys.insert(onetime_prekey.prekey, onetime_prekey);
        });

        X3DH {
            static_public_key: X25519PublicKey::from(&secret),
            secret,
            signed_prekey,
            onetime_prekeys,
            timestamp,
            ephemeral_prekeys: HashMap::default(),
            shared_secret: blake3::hash(&[0u8; 32]),
        }
    }

    pub fn prekey_bundle(&self) -> PrekeyBundle {
        PrekeyBundle {
            ik: self.static_public_key,
            spk: self.signed_prekey.prekey,
            spk_signature: self.signed_prekey.signature,
            opk: self.onetime_prekeys.values().take(1).next().unwrap().prekey, //TODO check if marked stale //TODO Handle `None` outcome
        }
    }

    pub fn new_ephemeral_key(&mut self, associated_public_key: X25519PublicKey) -> X25519PublicKey {
        let ek = EphemeralX25519Keypair::new(associated_public_key);
        let ek_public_key = ek.prekey;
        self.ephemeral_prekeys.insert(associated_public_key, ek);

        ek_public_key
    }

    pub fn dh_static1(&mut self, prekey_bundle: PrekeyBundle) -> &mut Self {
        //TODO handle more outcomes
        let dh1 = self.secret.diffie_hellman(&prekey_bundle.spk);
        self.shared_secret = blake3::hash(dh1.as_bytes());

        self
    }

    pub fn dh_static2(&mut self, prekey_bundle: PrekeyBundle) -> &mut Self {
        //TODO handle more outcomes
        let dh1 = self.signed_prekey.secret.diffie_hellman(&prekey_bundle.ik);

        self.shared_secret = blake3::hash(dh1.as_bytes());

        self
    }

    pub fn dh_ephemeral1(&mut self, prekey_bundle: &PrekeyBundle) -> blake3::Hash {
        let ik = prekey_bundle.ik;
        let spk = prekey_bundle.spk;
        let opk = prekey_bundle.opk;

        let ephemeral_keypair = self.ephemeral_prekeys.get(&ik).unwrap();
        let dh2 = ephemeral_keypair.secret.diffie_hellman(&ik);
        let mut hasher = blake3::Hasher::new();
        hasher.update(dh2.as_bytes());

        let dh3 = ephemeral_keypair.secret.diffie_hellman(&spk);
        hasher.update(dh3.as_bytes());

        let dh4 = ephemeral_keypair.secret.diffie_hellman(&opk);
        hasher.update(dh4.as_bytes());

        hasher.finalize()
    }

    pub fn dh_ephemeral2(
        &mut self,
        ek_public_key: &X25519PublicKey,
        opk: &X25519PublicKey,
    ) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();

        let dh2 = self.secret.diffie_hellman(&ek_public_key);
        hasher.update(dh2.as_bytes());

        let dh3 = self.signed_prekey.secret.diffie_hellman(&ek_public_key);
        hasher.update(dh3.as_bytes());
        let found_opk = self.onetime_prekeys.get(&opk).unwrap();

        let dh4 = found_opk.secret.diffie_hellman(&ek_public_key);
        hasher.update(dh4.as_bytes());

        hasher.finalize()
    }

    pub fn ik(&self) -> X25519PublicKey {
        self.static_public_key
    }
}

impl fmt::Debug for X3DH {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X3DH")
            .field("secret", &"[REDACTED]::<IK>")
            .field(
                "static_public_key",
                &hex::encode(&self.static_public_key.as_bytes()),
            )
            .field("signed_prekey", &self.signed_prekey)
            .field("onetime_prekeys", &self.onetime_prekeys)
            .field("timestamp", &self.timestamp)
            .field("shared_secret", &self.shared_secret.to_hex())
            .finish()
    }
}

pub struct SignedPrekey {
    signature: Ed25519Signature,
    secret: X25519Secret,
    prekey: X25519PublicKey,
    timestamp: Tai64N,
}

impl SignedPrekey {
    pub fn new(compute_signature: fn(&[u8]) -> Ed25519Signature) -> Self {
        let timestamp = Tai64N::now();
        let secret = X25519Secret::new(OsRng);
        let prekey_public_key = X25519PublicKey::from(&secret);
        let prekey_signature = compute_signature(prekey_public_key.as_bytes());

        SignedPrekey {
            secret,
            signature: prekey_signature,
            prekey: prekey_public_key,
            timestamp,
        }
    }
}

impl fmt::Debug for SignedPrekey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPrekey")
            .field("secret", &"[REDACTED]::<SPK>")
            .field("signature", &hex::encode(&self.signature.to_bytes()))
            .field("prekey", &hex::encode(&self.prekey.as_bytes()))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

pub struct OneTimePreKey {
    secret: X25519Secret,
    prekey: X25519PublicKey,
    timestamp: Tai64N,
    stale: bool,
}

impl OneTimePreKey {
    pub fn new() -> Self {
        let timestamp = Tai64N::now();
        let secret = X25519Secret::new(OsRng);
        let one_time_prekey = X25519PublicKey::from(&secret);

        OneTimePreKey {
            secret,
            prekey: one_time_prekey,
            timestamp,
            stale: bool::default(),
        }
    }
}

impl fmt::Debug for OneTimePreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimePreKey")
            .field("secret", &"[REDACTED]::<OPK>")
            .field("prekey", &hex::encode(&self.prekey.as_bytes()))
            .field("timestamp", &self.timestamp)
            .field("stale", &self.stale)
            .finish()
    }
}

pub struct EphemeralX25519Keypair {
    associated_public_key: X25519PublicKey,
    secret: X25519Secret,
    prekey: X25519PublicKey,
    timestamp: Tai64N,
}

impl EphemeralX25519Keypair {
    pub fn new(associated_public_key: X25519PublicKey) -> Self {
        let timestamp = Tai64N::now();
        let secret = X25519Secret::new(OsRng);
        let prekey = X25519PublicKey::from(&secret);

        EphemeralX25519Keypair {
            associated_public_key,
            secret,
            prekey,
            timestamp,
        }
    }
}

impl fmt::Debug for EphemeralX25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralX25519Keypair")
            .field("prekey", &hex::encode(&self.prekey.as_bytes()))
            .field("secret", &"[REDACTED]::<EK>")
            .field(
                "associated_public_key",
                &hex::encode(&self.associated_public_key.as_bytes()),
            )
            .field("timestamp", &self.timestamp)
            .finish()
    }
}
