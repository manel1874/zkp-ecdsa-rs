use openssl::ec::{EcGroup, EcGroupRef, EcPoint};
use openssl::bn::{BigNum, BigNumContext};
//use std::convert::TryFrom;

pub struct Commitment {
    g: &EcGroupRef,
    p: &EcPointRef,
    r: &BigNumRef,
}


impl Commitment {

    pub fn new(
        g: &EcGroupRef,
        p: &EcPointRef,
        r: &BigNumRef,
    ) -> Self {
        Commitment{ g, p, r }
    }

    pub fn add(
        &self, 
        c: &Commitment,
    ) -> Commitment {
        // Set curve | TODO: improve this approach
        //let group_name = self.g.curve_name().unwrap();
        //let group = *EcGroup::from_curve_name(group_name).unwrap().as_ref();
        // Compute sum of points
        let mut ctx = BigNumContext::new().unwrap();
        let mut sum_p = EcPoint::new(&self.g).unwrap();
        sum_p.add(&self.g, &self.p, &c.p, &mut ctx).unwrap();
        // Compute sum of random values
        let mut sum_r = BigNum::new().unwrap();
        sum_r.checked_add(&self.r, &c.r).unwrap();

        Commitment::new(self.g, sum_p, sum_r)
    }


    //fn mul()

    //fn sub()

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