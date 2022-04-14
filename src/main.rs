mod prekey_bundle;
mod types;
mod xxxdh;

pub use prekey_bundle::*;
pub use types::*;

use rand::rngs::OsRng;
pub use xxxdh::*;

fn main() {
    let mut alice = X3DH::new(SigCompute::sign);
    let mut bob = X3DH::new(SigCompute::sign);

    let alice_prekey_bundle = alice.prekey_bundle();
    let bob_prekey_bundle = bob.prekey_bundle();

    let alice_ek_prekey = alice.new_ephemeral_key(bob.ik());
    let bob_ek_prekey = bob.new_ephemeral_key(alice.ik());

    dbg!(&alice_prekey_bundle);
    dbg!(&bob_prekey_bundle);

    alice.dh_static1(bob_prekey_bundle);
    bob.dh_static2(alice_prekey_bundle);

    let shared_secret_alice = alice.dh_ephemeral1(&bob_prekey_bundle);
    let shared_secret_bob = bob.dh_ephemeral2(&alice_ek_prekey, &bob_prekey_bundle.opk);
    println!("ALICE {:?}", &shared_secret_alice);
    println!("BOB {:?}", &shared_secret_bob);

    assert_eq!(shared_secret_alice, shared_secret_bob)
}

pub const PROTOCOL_NAME: &str = "WASMIUM_XXX3DH";

pub struct SigCompute;

impl SigCompute {
    pub fn sign(value: &[u8]) -> Ed25519Signature {
        use ed25519_dalek::{Keypair, Signer};

        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        keypair.sign(value)
    }
}
