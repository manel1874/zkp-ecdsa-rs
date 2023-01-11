use std::error::Error;
use std::vec::Vec;
use num_bigint::BigUint;
use secp256k1::{Secp256k1, PublicKey};
use openssl::ec::EcGroup;
use openssl::bn::BigNum;

pub async fn prove_signature_list(
    params: &SystemParametersList,
    msg_hash: &[u8],
    sig_bytes: &[u8],
    public_key: &PublicKey,
    which: usize,
    keys: &[BigUint],
) -> Result<SignatureProofList, Box<dyn Error>> {
    let ec = Secp256k1::new();
    let group_order = ec.curve_order();
    let pk_bytes = public_key.serialize();
    let pk_point = ec.decompress_point(&pk_bytes);

    if pk_point.is_none() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid public key",
        )));
    }
    let pk_point = pk_point.unwrap();
    let len = sig_bytes.len();
    let z = truncate_to_n(from_bytes(msg_hash), &group_order);
    let r = from_bytes(&sig_bytes[0..(len/2)]);
    let s = from_bytes(&sig_bytes[(len/2)..]);

    let sinv = inv_mod(s, &group_order);
    let u1 = pos_mod(sinv * &z, &group_order);
    let u2 = pos_mod(sinv * &r, &group_order);
    let R = ec.g().mul_scalar(&u1).add_p(&pk_point.mul_scalar(&u2));
    let rinv = inv_mod(r, &group_order);
    let s1 = pos_mod(rinv * s, &group_order);
    let z1 = pos_mod(rinv * z, &group_order);
    let Q = ec.g().mul_scalar(&z1);
    let params_sig_exp = PedersenParams::new(ec, R, &params.nist_group.h);
    let com_s1 = params_sig_exp.commit(s1);
    let pk_x = params.proof_group.commit(pk_point.x);
    let pk_y = params.proof_group.commit(pk_point.y);
    let sig_proof = prove_exp(params_sig_exp, &params.proof_group, s1, com_s1, pk_point, pk_x, pk_y, &params.sec_level, Q)?;
    let membership_proof = prove_membership(&params.proof_group, pk_x, which, keys)?;

    Ok(SignatureProofList {
        R,
        com_s1,
        pk_x,
        pk_y,
        sig_proof,
        membership_proof
    })
}



fn main() {
    println!("Hello, world!");
}
