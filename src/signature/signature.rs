use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};

use crate::commit::pedersen::{Commitment, PedersenParams, generate_random};
use crate::commit::mult::{MultProof, prov_mult, aggregate_mult};
use crate::commit::equality::{EqualityProof, prove_equality, aggregate_equality};
use crate::curves::multimult::{MultiMult, Relation};
use crate::equality::hash_points;
use crate::exp::exp::ExpProof;



pub struct SignatureProof<'a> {
    pub groupNIST: &'a EcGroupRef,
    pub groupWario: &'a EcGroupRef,
    pub R: EcPoint,
    pub comS1: EcPoint,
    pub keyXcom: EcPoint,
    pub keyYcom: EcPoint,
    pub expProof: ExpProof<'a>,
}

impl<'a> SignatureProof<'a> {
    pub fn eq(&self, other: &Self) -> bool {

        let mut ctx = BigNumContext::new().unwrap();

        self.R.eq(self.groupNIST, &other.R, &mut ctx).unwrap() &&
        self.comS1.eq(self.groupWario, &other.comS1, &mut ctx).unwrap() &&
        self.keyXcom.eq(self.groupWario, &other.keyXcom, &mut ctx).unwrap() &&
        self.keyYcom.eq(self.groupWario, &other.keyYcom, &mut ctx).unwrap() &&
        self.expProof.eq(&other.expProof)
    }
}


pub struct SystemParameters<'a> {
    pub groupNIST: &'a EcGroupRef,
    pub groupWario: &'a EcGroupRef,
    pub secLevel: usize
}

fn shr(self, n: i32) -> BigNum {
    let mut r = BigNum::new().unwrap();
    let delta = self.num_bits() - n.num_bits();
    if delta > 0 {
        r.rshift(self, n).unwrap();
    }
    
    r
}

/* function truncateToN(msg: bigint, n: bigint): bigint {
    const delta = bitLen(msg) - bitLen(n)
    if (delta > 0) {
        msg >>= BigInt(delta)
    }
    return msg
} */