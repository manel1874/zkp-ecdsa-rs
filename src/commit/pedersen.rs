use openssl::ec::{EcGroupRef, EcPoint};
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::error::ErrorStack;
//use std::convert::TryFrom;

pub struct Commitment<'a> {
    pub group: &'a EcGroupRef,
    pub p: EcPoint,
    pub r: BigNum,
}


impl<'a> Commitment<'a> {

    pub fn new(
        group: &'a EcGroupRef,
        p: EcPoint,
        r: BigNum,
    ) -> Self {
        Commitment{ group, p, r }
    }
    
    pub fn to_owned(&self) -> Self {
        Commitment{
            group: &self.group,
            p: self.p.to_owned(&self.group).unwrap(),
            r: self.r.to_owned().unwrap()
        }
    }

    /// Takes a commitment c and adds to self
    pub fn add(&self, c: &Self) -> Self {

        let mut ctx = BigNumContext::new().unwrap();
        
        // Take group order
        let mut order_curve = BigNum::new().unwrap();
        self.group.order(&mut order_curve, &mut ctx).unwrap();

        // Update p: sum_p = self.p + c.p
        let mut sum_p = EcPoint::new(&self.group).unwrap();
        sum_p.add(&self.group, &self.p, &c.p, &mut ctx).unwrap();
        
        
        // Update r: sum_r = self.r + c.r
        let mut sum_r = BigNum::new().unwrap();
        sum_r.mod_add(&self.r, &c.r, &order_curve, &mut ctx).unwrap();


        Commitment{ 
            group: &self.group, 
            p: sum_p, 
            r: sum_r }
    }


    /// Takes a commitment c and subs to self
    pub fn sub(&self, c: &Self) -> Self {

        let mut ctx = BigNumContext::new().unwrap();

        // Take group order
        let mut order_curve = BigNum::new().unwrap();
        self.group.order(&mut order_curve, &mut ctx).unwrap();

        // Update p: sum_p = self.p - c.p
        let mut sub_p = EcPoint::new(&self.group).unwrap();
        // // invert c.p
        let inv = BigNum::from_dec_str("-1").unwrap(); 
        let mut neg_c_p = EcPoint::new(&self.group).unwrap();
        neg_c_p.mul(&self.group, &self.p, &inv, &mut ctx).unwrap();
        // // add -c.p to it
        sub_p.add(&self.group, &self.p, &neg_c_p, &mut ctx).unwrap();
        
        // Update r: sum_r = self.r - c.r
        let mut sub_r = BigNum::new().unwrap();
        sub_r.mod_sub(&self.r, &c.r, &order_curve, &mut ctx).unwrap();

        Commitment{ 
            group: &self.group, 
            p: sub_p, 
            r: sub_r }
    }


    /// Takes an integer k and multiplies the self by k
    pub fn mul(&mut self, k: &BigNum) -> Self {

        let mut ctx = BigNumContext::new().unwrap();

        // Take group order
        let mut order_curve = BigNum::new().unwrap();
        self.group.order(&mut order_curve, &mut ctx).unwrap();

        // Update p: mul_p = k * self.p
        let mut mul_p = EcPoint::new(&self.group).unwrap();
        mul_p.mul(&self.group, &self.p, k, &mut ctx).unwrap();

        // Update r: mul_r = k * self.r 
        let mut mul_r = BigNum::new().unwrap();
        mul_r.mod_mul(&self.r, k, &order_curve, &mut ctx).unwrap();

        Commitment{ 
            group: &self.group, 
            p: mul_p, 
            r: mul_r }

    }

}



pub struct PedersenParams<'a> {
    pub c: &'a EcGroupRef,
    pub g: EcPoint,
    pub h: EcPoint,
}


impl<'a> PedersenParams<'a> {

    pub fn new(
        c: &'a EcGroupRef,
        g: EcPoint, // Note:: currently g is not being used because it is taken 
                    //        the generator of curve c.
        h: EcPoint,
    ) -> Self {
        PedersenParams{ c, g, h }
    }

    pub fn eq(&self, o: &PedersenParams) -> bool {

        let mut ctx = BigNumContext::new().unwrap();
        
        self.g.eq(self.c, &o.g, &mut ctx).unwrap() &&
        self.h.eq(self.c, &o.h, &mut ctx).unwrap() 
    }

    pub fn commit(&self, input: &BigNum) -> Commitment {

        let mut ctx = BigNumContext::new().unwrap();

        // Random element
        let mut r = BigNum::new().unwrap();
        let mut n_order = BigNum::new().unwrap();
        let _ = &self.c.order(&mut n_order, &mut ctx).unwrap();
        // Generates a 256-bit odd random number
        let nbits = n_order.num_bits();

        r.rand(nbits, MsbOption::MAYBE_ZERO, true).unwrap();

        // Computes g * input + h * r, storing the result in self.
        let mut p = EcPoint::new(&self.c).unwrap();
        p.mul_full(
            &self.c, 
            input,
            &self.h,
            &r,
            &mut ctx).unwrap();
        
        Commitment{group: &self.c, p, r}
    }
}

/*

        UTIL::groups

*/
pub fn generate_random(order_curve: &BigNum) -> Result< BigNum, ErrorStack > {
    /* ------ old version --------
    let mut big = BigNum::new().unwrap();
 
    // Generates a 128-bit odd random number
    big.rand(128, MsbOption::MAYBE_ZERO, true);
    */

    let mut big_rnd = BigNum::new().unwrap();
    order_curve.rand_range(&mut big_rnd);

    Ok(big_rnd)
 }



pub fn generate_pedersen_params(c: &EcGroupRef) -> PedersenParams {
    
    let mut ctx = BigNumContext::new().unwrap();
    
    let g = c.generator();

    let mut order_curve = BigNum::new().unwrap();
    c.order(&mut order_curve, &mut ctx).unwrap();
    let r = generate_random(&order_curve).unwrap();

    
    let mut h = EcPoint::new(&c).unwrap();
    h.mul(&c, &g, &r, &mut ctx).unwrap();

    let g_deref = g.to_owned(c).unwrap();

    PedersenParams::new(&c, g_deref, h)
}

