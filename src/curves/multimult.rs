use std::cmp::Ordering;

use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::bn::BigNum;

pub struct Pair {
    pub pt: EcPoint,
    pub scalar: BigNum
}

impl Pair {
    pub fn new(pt: EcPoint, scalar: BigNum) -> Self {
        Pair { pt, scalar }
    }

    pub fn cmp(&self, b: &Pair) -> Ordering {
        self.scalar.cmp(&b.scalar)
    }
}

pub struct Ptidx {
    pub pt: EcPoint,
    pub idx: usize
}

pub struct MultiMult<'a> {
    group: &'a EcGroupRef,
    pairs: Vec<Pair>,
    known: Vec<Ptidx>,
}



impl<'a> MultiMult<'a> {
    fn new(g: &'a EcGroupRef) -> Self {
        MultiMult {
            group: g,
            pairs: vec![],
            known: vec![],
        }
    }
}



/*
pub struct Pair {
    pub pt: Point,
    pub scalar: Scalar,
}

impl Pair {
    pub fn new(pt: Point, scalar: Scalar) -> Self {
        Pair { pt, scalar }
    }

    pub fn cmp(&self, b: &Pair) -> std::cmp::Ordering {
        self.scalar.cmp(&b.scalar)
    }
}


TODO: keep doing the multimult in rust. This is used a lot! Once you do it the other proofs are much much faster!

*/