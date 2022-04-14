use crate::types::*;
use core::fmt;

#[derive(Clone, Copy)]
pub struct PrekeyBundle {
    pub ik: X25519PublicKey,
    pub spk: X25519PublicKey,
    pub spk_signature: Ed25519Signature,
    pub opk: X25519PublicKey,
}

impl fmt::Debug for PrekeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrekeyBundle")
            .field("ik", &hex::encode(self.ik.as_bytes()))
            .field("spk", &hex::encode(self.spk.as_bytes()))
            .field(
                "spk_signature",
                &hex::encode(&self.spk_signature.to_bytes()),
            )
            .field("opk", &hex::encode(self.opk.as_bytes()))
            .finish()
    }
}
