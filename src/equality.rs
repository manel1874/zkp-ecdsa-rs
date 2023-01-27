//use serde::{Serialize, Deserialize};
//use curve25519_dalek::ristretto::{RistrettoPoint, Scalar};
//use sha2::{Sha256, Digest};
//use std::convert::TryFrom;

use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef};
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::error::ErrorStack;

//#[derive(Serialize, Deserialize)]
pub struct EqualityProof<'a> {
    pub group: &'a EcGroupRef,
    pub A_1: EcPoint,
    pub A_2: EcPoint,
    pub t_x: BigNum,
    pub t_r1: BigNum,
    pub t_r2: BigNum,
}

impl<'a> EqualityProof<'a> {
    fn eq(&self, other: &EqualityProof) -> bool {
        
        let mut ctx = BigNumContext::new().unwrap();

        self.A_1.eq(self.group, &other.A_1, &mut ctx).unwrap()
        
        /* 
        &&
        self.A_2 == other.A_2 &&
        self.t_x == other.t_x &&
        self.t_r1 == other.t_r1 &&
        self.t_r2 == other.t_r2
        */
    }
}

/* 
struct PedersenParams {
    c: RistrettoPoint,
    g: RistrettoPoint,
    h: RistrettoPoint,
}

struct Commitment {
    p: RistrettoPoint,
    r: Scalar,
}

fn hash_points(points: &[RistrettoPoint]) -> Scalar {
    let mut hasher = Sha256::new();
    for point in points {
        hasher.input(point.compress().as_bytes());
    }
    let result = hasher.result();
    Scalar::try_from(&result[..]).unwrap()
}

async fn prove_equality(
    params: PedersenParams,
    x: u64,
    C1: Commitment,
    C2: Commitment
) -> EqualityProof {
    let k = Scalar::random(&mut rand::thread_rng()),
        A1 = params.c * k,
        A2 = params.c * k,
        c = hash_points(&[C1.p, C2.p, A1, A2]),
        xx = Scalar::from(x),
        tx = k - c * xx,
        tr1 = A1.r - c * C1.r,
        tr2 = A2.r - c * C2.r;

    EqualityProof { A_1: A1, A_2: A2, t_x: tx, t_r1: tr1, t_r2: tr2 }
}

*/