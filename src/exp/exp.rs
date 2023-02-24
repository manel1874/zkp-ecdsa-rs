use rand::prelude::thread_rng;

use openssl::ec::{EcGroupRef, EcPoint, PointConversionForm};
use openssl::bn::{BigNum, BigNumContext};

use crate::exp::pointAdd::PointAddProof;








pub fn padded_bits(val: &BigNum, length: usize) -> Vec<bool> {
    
    let mut ret = Vec::with_capacity(length);

    let mut num = val.as_ref().to_owned().unwrap();

    for i in 0..length {
        let int = num.to_owned().unwrap();
        let bit_set = num.is_bit_set(0);
        num.rshift1(&int).unwrap();
        //println!("1011 {}-th is {}: ", i, bit_set);
        ret.push(bit_set)
    }
    //println!("Ret vec is {:?}: ", ret);
    ret
} 

fn generate_indices(indnum: usize, limit: usize) -> Vec<usize> {
    
    // We are not using the Algorithm P

    //The algorithm below is based on Durstenfeld's algorithm for the
    // [Fisher–Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm)

    // Aim: use a cryptographically secure pseudo RNG (CSPRNG)

    /* 
    use rand::{seq::SliceRandom, RngCore};
    use rand::rngs::OsRng;

    fn secure_shuffle<T: Copy>(v: &mut Vec<T>) {
        let mut rng = OsRng;
        v.shuffle(&mut rng);
    } */

    // HERE: use thread_rng.shuffle() : 
    // https://stackoverflow.com/questions/26033976/how-do-i-create-a-vec-from-a-range-and-shuffle-it
    // https://docs.rs/rand/latest/rand/seq/trait.SliceRandom.html#tymethod.shuffle
    
    let mut ret = (0..limit).collect::<Vec<usize>>();
    let mut rng = thread_rng();
    for i in 0..limit - 2 {
        let j = rng.gen_range(i, limit);
        ret.swap(i, j);
    }
    ret.split_off(indnum);
    ret
}




pub struct ExpProof<'a> {
    pub group: &'a EcGroupRef,
    pub a: EcPoint,
    pub t_x: EcPoint,
    pub t_y: EcPoint,
    // Response 1
    pub alpha: Option<BigNum>,
    pub beta1: Option<BigNum>,
    pub beta2: Option<BigNum>,
    pub beta3: Option<BigNum>,
    // Response 2
    pub z: Option<BigNum>,
    pub z2: Option<BigNum>,
    pub proof: Option<PointAddProof<'a>>,
    pub r1: Option<BigNum>,
    pub r2: Option<BigNum>,
}


impl<'a> ExpProof<'a> {
    pub fn eq(&self, other: &Self) -> bool {
        
        let mut ctx = BigNumContext::new().unwrap();
        //  define c0
        let c0 = self.a.eq(self.group, &other.a, &mut ctx).unwrap() &&
                self.t_x.eq(self.group, &other.t_x, &mut ctx).unwrap() &&
                self.t_y.eq(self.group, &other.t_y, &mut ctx).unwrap();
        
        // define r0
        let cmp_alpha = if self.alpha.is_some() && other.alpha.is_some() {
                            self.alpha.as_ref().unwrap() == other.alpha.as_ref().unwrap()
                        } else {
                            false
                        };

        let cmp_beta1 = if self.beta1.is_some() && other.beta1.is_some() {
                            self.beta1.as_ref().unwrap() == other.beta1.as_ref().unwrap()
                        } else {
                            false
                        };

        let cmp_beta2 = if self.beta2.is_some() && other.beta2.is_some() {
                            self.beta2.as_ref().unwrap() == other.beta2.as_ref().unwrap()
                        } else {
                            false
                        };

        let cmp_beta3 = if self.beta3.is_some() && other.beta3.is_some() {
                            self.beta3.as_ref().unwrap() == other.beta3.as_ref().unwrap()
                        } else {
                            false
                        };

        let r0 = cmp_alpha && cmp_beta1 && cmp_beta2 && cmp_beta3;

        // define r1
        let cmp_z = if self.z.is_some() && other.z.is_some() {
                            self.z.as_ref().unwrap() == other.z.as_ref().unwrap()
                        } else {
                            false
                        };

        let cmp_z2 = if self.z2.is_some() && other.z2.is_some() {
                            self.z2.as_ref().unwrap() == other.z2.as_ref().unwrap()
                        } else {
                            false
                        };


        let cmp_proof = if self.proof.is_some() && other.proof.is_some() {
                            self.proof.as_ref().unwrap().eq(&other.proof.as_ref().unwrap())
                        } else {
                            false
                        };

        let cmp_r1 = if self.r1.is_some() && other.r1.is_some() {
                            self.r1.as_ref().unwrap() == other.r1.as_ref().unwrap()
                        } else {
                            false
                        };
        
        let cmp_r2 = if self.r2.is_some() && other.r2.is_some() {
                            self.r2.as_ref().unwrap() == other.r2.as_ref().unwrap()
                        } else {
                            false
                        };

        let r1 = cmp_z && cmp_z2 && cmp_proof && cmp_r1 && cmp_r2;


        r0 && (r0 || r1)
    }
}

