//use serde::{Serialize, Deserialize};
//use curve25519_dalek::ristretto::{RistrettoPoint, Scalar};
//use sha2::{Sha256, Digest};
//use std::convert::TryFrom;

use openssl::ec::{EcGroupRef, EcPoint, PointConversionForm};
use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};

use crate::commit::pedersen::{Commitment, PedersenParams, generate_random};
use crate::curves::multimult::{MultiMult, Relation};



//use std::convert::TryFrom;
//use std::future::Future;
//use std::pin::Pin;

/*

            UTIL::groups

*/


pub fn hash_points(hash_id: MessageDigest, groups: &[&EcGroupRef], points: &[&EcPoint]) -> Result< BigNum, ErrorStack > {  //-> impl Future<Output = Result<u128, ()>> {
    
    //async move {

        let mut ctx = BigNumContext::new().unwrap();

        let bytes_points: Vec<_>; 
        if groups.len() == 1 {
            bytes_points = points.iter().map(|p| p.to_bytes(groups[0], PointConversionForm::COMPRESSED, &mut ctx).unwrap()).collect();
        } else {
            bytes_points = groups.iter().zip(points.iter()).map(|(g, p)| p.to_bytes(g, PointConversionForm::COMPRESSED, &mut ctx).unwrap()).collect();
        }
        // bytes_points is a vec< [g.to_bytes, h.to_bytes]>
        

        // flatten bytes_points

        /* ====== as in .ts version
                
        // total size of bytes_points to create a new bytes vec

        let size : usize = bytes_points.iter().map(|b| b.len()).sum();
        let mut bytes = vec![0u8; size].into_boxed_slice();
        let mut offset = 0;

        for bp in &bytes_points {
            bytes[offset..offset + bp.len()].copy_from_slice(bp);
            offset += bp.len();
        }
        ==================================*/
        let flatten_bytes: Vec<_> = bytes_points.into_iter().flat_map(|x| x).collect();

        let hash = openssl::hash::hash(hash_id, &flatten_bytes[..]).map_err(|_| ()).unwrap();
        BigNum::from_slice(&hash[..10])
    //}
}



//#[derive(Serialize, Deserialize)]
pub struct EqualityProof<'a> {
    pub group: &'a EcGroupRef,
    pub a_1: EcPoint,
    pub a_2: EcPoint,
    pub t_x: BigNum,
    pub t_r1: BigNum,
    pub t_r2: BigNum,
}


impl<'a> EqualityProof<'a> {
    pub fn eq(&self, other: &EqualityProof) -> bool {
        
        let mut ctx = BigNumContext::new().unwrap();

        self.a_1.eq(self.group, &other.a_1, &mut ctx).unwrap() &&
        self.a_2.eq(self.group, &other.a_2, &mut ctx).unwrap() &&
        self.t_x == other.t_x &&
        self.t_r1 == other.t_r1 &&
        self.t_r2 == other.t_r2
    }
}

/**
 * ZK(x, r1, r2: C1 = xG + r1H and C2 = xG + r2H)
 *
 * @param params
 * @param x
 * @param C1
 * @param C2
 */
pub fn prove_equality<'a>(
    params: &'a PedersenParams<'a>,
    x: BigNum,
    C1: Commitment,
    C2: Commitment
)-> EqualityProof<'a> {

    let mut ctx = BigNumContext::new().unwrap();

    let mut order_curve = BigNum::new().unwrap();
    params.c.order(&mut order_curve, &mut ctx).unwrap();
    let k = generate_random(&order_curve).unwrap(); //Scalar::random(&mut rand::thread_rng());

    let A1 = params.commit(&k);
    let A2 = params.commit(&k);

    let c = hash_points(MessageDigest::sha256(), &[params.c], &[&C1.p, &C2.p, &A1.p, &A2.p]).unwrap();

    let mut cc = BigNum::new().unwrap();
    cc.nnmod(&c, &order_curve, &mut ctx).unwrap();
    let mut xx = BigNum::new().unwrap();
    xx.nnmod(&x, &order_curve, &mut ctx).unwrap();
    let mut kk = BigNum::new().unwrap();
    kk.nnmod(&k, &order_curve, &mut ctx).unwrap();


    // Compute  t_x = k - c * x
    let mut cc_times_xx = BigNum::new().unwrap();
    cc_times_xx.mod_mul(&cc, &xx, &order_curve, &mut ctx).unwrap();       
    let mut t_x = BigNum::new().unwrap();
    t_x.mod_sub(&kk,  &cc_times_xx, &order_curve, &mut ctx).unwrap();
    
    // Compute t_r1 = s1 - c * r1
    let mut cc_times_r1 = BigNum::new().unwrap();
    cc_times_r1.mod_mul(&cc, &C1.r, &order_curve, &mut ctx).unwrap();     
    let mut t_r1 = BigNum::new().unwrap();
    t_r1.mod_sub(&A1.r, &cc_times_r1, &order_curve, &mut ctx).unwrap();

    // Compute t_r2 = s2 - c * r2
    let mut cc_times_r2 = BigNum::new().unwrap();
    cc_times_r2.mod_mul(&cc, &C2.r, &order_curve, &mut ctx).unwrap();   
    let mut t_r2 = BigNum::new().unwrap();
    t_r2.mod_sub(&A2.r, &cc_times_r2, &order_curve, &mut ctx).unwrap();

    EqualityProof {
        group: params.c,
        a_1: A1.p,
        a_2: A2.p,
        t_x: t_x,
        t_r1: t_r1,
        t_r2: t_r2,
    }

}

pub fn verify_equality<'a>(
    params: &'a PedersenParams<'a>,
    C1: EcPoint,
    C2: EcPoint,
    pi: &'a EqualityProof<'a>
) -> bool {
    
    let mut multi = MultiMult::new(params.c);

    let ok = aggregate_equality(params, C1, C2, pi, &mut multi);

    if !ok {
        return false
    }
    
    multi.evaluate().is_infinity(&params.c)
}


pub fn aggregate_equality<'a> (
    params: &'a PedersenParams<'a>,
    C1: EcPoint,
    C2: EcPoint,
    pi: &'a EqualityProof<'a>,
    multi: &mut MultiMult
) -> bool {

    let mut ctx = BigNumContext::new().unwrap();

    let challenge = hash_points(MessageDigest::sha256(), &[params.c], &[&C1, &C2, &pi.a_1, &pi.a_2]).unwrap();
    // new scalar challenge
    let mut order_curve = BigNum::new().unwrap();
    params.c.order(&mut order_curve, &mut ctx).unwrap();
    let mut cc = BigNum::new().unwrap();
    cc.nnmod(&challenge, &order_curve, &mut ctx).unwrap();


    let mut A1rel = Relation::new(params.c);
    A1rel.insert(params.g.to_owned(&params.c).unwrap(), pi.t_x.to_owned().unwrap());
    A1rel.insert(params.h.to_owned(&params.c).unwrap(), pi.t_r1.to_owned().unwrap());
    A1rel.insert(C1, cc.to_owned().unwrap());
    // pi.a_1.invert(&params.c, &mut ctx);
    // invert function cannot be used because:
    // `pi` is a `&` reference, so the data it refers to cannot be borrowed as mutable
    let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
    let mut minus_a_1 = EcPoint::new(&params.c).unwrap();
    minus_a_1.mul(&params.c, &pi.a_1, &minus_1, &mut ctx).unwrap();
    A1rel.insert(minus_a_1, BigNum::from_u32(1).unwrap());
    
    let mut A2rel = Relation::new(params.c);
    A2rel.insert(params.g.to_owned(&params.c).unwrap(), pi.t_x.to_owned().unwrap());
    A2rel.insert(params.h.to_owned(&params.c).unwrap(), pi.t_r2.to_owned().unwrap());
    A2rel.insert(C2, cc.to_owned().unwrap());
    // pi.a_1.invert(&params.c, &mut ctx);
    // invert function cannot be used because:
    // `pi` is a `&` reference, so the data it refers to cannot be borrowed as mutable
    let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
    let mut minus_a_2 = EcPoint::new(&params.c).unwrap();
    minus_a_2.mul(&params.c, &pi.a_2, &minus_1, &mut ctx).unwrap();
    A2rel.insert(minus_a_2, BigNum::from_u32(1).unwrap());
    
    A1rel.drain(multi);
    A2rel.drain(multi);

    true
}