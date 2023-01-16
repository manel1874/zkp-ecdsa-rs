use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef};
use openssl::bn::{BigNum, BigNumRef, BigNumContext};
//use std::convert::TryFrom;

pub struct Commitment<'a> {
    pub g: &'a EcGroupRef,
    pub p: EcPoint,
    pub r: BigNum,
}


impl<'a> Commitment<'a> {

    pub fn new(
        g: &'a EcGroupRef,
        p: EcPoint,
        r: BigNum,
    ) -> Self {
        Commitment{ g, p, r }
    }
    

    /// Takes a commitment c and adds to self
    pub fn add(&mut self, c: &Commitment) {

        let mut ctx = BigNumContext::new().unwrap();

        // Update p: sum_p = self.p + c.p
        let mut sum_p = EcPoint::new(&self.g).unwrap();
        sum_p.add(&self.g, &self.p, &c.p, &mut ctx).unwrap();
        self.p = sum_p;
        
        // Update r: sum_r = self.r + c.r
        let mut sum_r = BigNum::new().unwrap();
        sum_r.checked_add(&self.r, &c.r).unwrap();
        self.r = sum_r;
    }


    /// Takes a commitment c and subs to self
    pub fn sub(&mut self, c: &Commitment) {

        let mut ctx = BigNumContext::new().unwrap();

        // Update p: sum_p = self.p - c.p
        let mut sub_p = EcPoint::new(&self.g).unwrap();
        // // invert c.p
        let inv = BigNum::from_dec_str("-1").unwrap(); 
        let mut neg_c_p = EcPoint::new(&self.g).unwrap();
        neg_c_p.mul(&self.g, &self.p, &inv, &mut ctx).unwrap();
        // // add -c.p to it
        sub_p.add(&self.g, &self.p, &neg_c_p, &mut ctx).unwrap();
        self.p = sub_p;
        
        // Update r: sum_r = self.r + c.r
        let mut sum_r = BigNum::new().unwrap();
        sum_r.checked_sub(&self.r, &c.r).unwrap();
        self.r = sum_r;
    }


    /// Takes an integer k and multiplies the self by k
    pub fn mul(&mut self, k: &BigNum) {

        let mut ctx = BigNumContext::new().unwrap();

        // Update p: mul_p = k . self.p
        let mut mul_p = EcPoint::new(&self.g).unwrap();
        mul_p.mul(&self.g, &self.p, k, &mut ctx).unwrap();
        self.p = mul_p;

        // Update r: mul_r = k . self.r 
        let mut mul_r = BigNum::new().unwrap();
        mul_r.checked_mul(&self.r, k, &mut ctx).unwrap();
        self.r = mul_r;

    }

}

/* 
impl Commitment {
    fn new(p: EcPoint, r: BigInt) -> Self {
        Commitment { p, r }
    }
    fn add(&self, c: &Commitment) -> Commitment {
        let p = self.p.add(&c.p).unwrap();
        let r = self.r.clone() + &c.r;
        Commitment::new(p, r)
    }
    fn mul(&self, k: &BigInt) -> Commitment {
        let sk = BigUint::from_bigint(k);
        let sk = match sk {
            Some(sk) => sk,
            None => return Commitment::new(EcPoint::new(self.p.group()).unwrap(), BigInt::zero()),
        };
        let sk = EcScalar::from(sk);
        let p = self.p.mul(&sk).unwrap();
        let r = &self.r * k;
        Commitment::new(p, r)
    }
    fn sub(&self, c: &Commitment) -> Commitment {
        let p = self.p.sub(&c.p).unwrap();
        let r = self.r.clone() - &c.r;
        Commitment::new(p, r)
    }
}

struct PedersenParams {
    c: EcGroup,
    g: EcPoint,
    h: EcPoint,
}

impl PedersenParams {
    fn new(c: EcGroup, g: EcPoint, h: EcPoint) -> Self {
        PedersenParams { c, g, h }
    }
    fn eq(&self, o: &PedersenParams) -> bool {
        self.c == o.c && self.g == o.g && self.h == o.h
    }
    fn commit(&self, input: &BigInt) -> Commitment {
        let r = BigInt::rand(256);
        let v = BigUint::from_bigint(input);
        let v = match v {
            Some(v) => v,
            None => return Commitment::new(EcPoint::new(self.c).unwrap(), BigInt::zero()),
        };
        let v = EcScalar::from(v);
        let p = self.h.mul_with_scalars(&[&r, &v]).unwrap();
        Commitment::new(p, r)
    }
}

fn generate_pedersen_params(c: &EcGroup, g: Option<&EcPoint>) -> PedersenParams {
    let g = g.unwrap_or_else(|| c.generator().unwrap());
    let r = BigInt::rand(256);
    let h = g.mul(&r).unwrap();
    PedersenParams::new(c.clone(), g.clone(), h)
}

*/