/* use std::error::Error;
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
        members hip_proof
    })
}
*/

//use secp256k1;

/*
async fn prove_point_add(
    params: PedersenParams,
    P: GroupPoint,
    Q: GroupPoint,
    R: GroupPoint,
    PX: Commitment,
    PY: Commitment,
    QX: Commitment,
    QY: Commitment,
    RX: Commitment,
    RY: Commitment
) -> Result<PointAddProof, Box<dyn Error>> {
    if !P.add(Q).eq(R) {
        return Err(From::from("Points don't add up!"));
    }
    let prime = params.c.order;
    let C1 = PX;
    let C2 = QX;
    let C3 = RX;
    let C4 = PY;
    let C5 = QY;
    let C6 = RY;
    let coord_p = P.to_affine();
    let coord_q = Q.to_affine();
    let coord_r = R.to_affine();
    if coord_p.is_none() {
        return Err(From::from("P is at infinity"));
    }
    if coord_q.is_none() {
        return Err(From::from("Q is at infinity"));
    }
    if coord_r.is_none() {
        return Err(From::from("R is at infinity"));
    }
    let coord_p = coord_p.unwrap();
    let coord_q = coord_q.unwrap();
    let coord_r = coord_r.unwrap();
    let x1 = coord_p.x;
    let y1 = coord_p.y;
    let x2 = coord_q.x;
    let y2 = coord_q.y;
    let x3 = coord_r.x;
    let i7 = pos_mod(x2 - x1, prime);
    let i8 = inv_mod(i7, prime);
    let i9 = pos_mod(y2 - y1, prime);
    let i10 = pos_mod(i8 * i9, prime);
    let i11 = pos_mod(i10 * i10, prime);
    let i12 = pos_mod(x1 - x3, prime);
    let i13 = pos_mod(i10 * i12, prime);
    let C7 = C2.sub(C1);
    let C8 = params.commit(i8);
    let C9 = C5.sub(C4);
    let C10 = params.commit(i10);
    let C11 = params.commit(i11);
    let C12 = C1.sub(C3);
    let C13 = params.commit(i13);
    let C14 = Commitment::new(params.g, params.c.new_scalar(BigInt::from(0)));
    let pi8 = await prove_mult(params, i7, i8, BigInt::from(1), C7, C8, C14)?;
    let pi10 = await prove_mult(params, i8, i9, i10, C8, C9, C10)?;
    let pi11 = await prove_mult(params, i10, i10, i11, C10, C10, C11)?;

    let Cint = C3.p + C1.p + C2.p;
    let pix = await prove_equality(params, i11, C11, Cint)?;
    let pi12 = await prove_mult(params, i10, i12, i13, C10, C12, C13)?;

    let Cint = C6.p + C4.p;
    let piy = await prove_equality(params, i13, C13, Cint)?;
    
    Ok(PointAddProof{C8,C9,C10,C11,C12,C13,pi8,pi10,pi11,pix,pi12,piy})
}

*/


// use std::error::Error;
use openssl::ec::{EcGroup, EcPoint};
pub mod pedersen;

use openssl::nid::Nid;
use openssl::bn::{BigNum};



fn main() {
    println!("Hello, world!");

     
    // Create a new P256 curve object
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    // Generate two poins randomly
    //let P1 = EcKey::generate(&group)?;
    //let p2 = EcKey::generate(&group).unwrap();
    //let p = group.generator();
    let point = EcPoint::new(&group).unwrap();

    let n43 = "43";
    let n2 = "2";
    let mut res = BigNum::new().unwrap();
    let bign43 = BigNum::from_dec_str(n43).unwrap();
    let bign2 = BigNum::from_dec_str(n2).unwrap();
    
    res.checked_add(&bign43,&bign2).unwrap();

    println!("{}", res);

    let com1 = pedersen::Commitment::new(group, point, bign43);
    let com2 = pedersen::Commitment::new(group, point, bign43);

}
