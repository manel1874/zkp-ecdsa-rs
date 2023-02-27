use rand::{seq::SliceRandom, RngCore};
use rand::rngs::OsRng;
use openssl::hash::{hash, MessageDigest};

use openssl::ec::{EcGroup, EcGroupRef, EcPoint, PointConversionForm};
use openssl::bn::{BigNum, BigNumContext};
use crate::commit::pedersen::{Commitment, PedersenParams, generate_random};

use crate::exp::pointAdd::PointAddProof;

use crate::equality::hash_points;



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

pub fn generate_indices(indnum: usize, limit: usize) -> Vec<usize> {
    
    /*  We are not using the Algorithm P. The algorithm below is based on 
    Durstenfeld's algorithm for the [Fisher–Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm)
    */

    let mut ret = (0..limit).collect::<Vec<usize>>();
    let mut rng = OsRng; // CSPRNG
    let interval = limit - indnum;

    let ret_shuffled;

    if interval < 0 {
        ret_shuffled = vec![];
    } else {
        ret_shuffled = ret.as_mut_slice().partial_shuffle(&mut rng, interval).0.to_vec();
    }
    
    ret_shuffled
}

/**
 * ZK(s, r, rx, ry: sR = P + Q and Cs = sR + rS and Cx = Px G + rx H and Cy = Py G + ry H) [Q is optional]
 * paramsNIST.g = R [Point R must be populated in the g field of paramsNIST]
 *
 * @param paramsNIST NIST params
 * @param paramsWario Wario params
 * @param s secret
 * @param Cs: commitment to the secret with params NIST
 * @param rx
 * @param ry
 * @param Px
 * @param Py
 * @param Q an optional public point
 * @param secparam Soundness error
 */
pub fn prov_exp<'a>(
    paramsNIST: &'a PedersenParams<'a>,
    paramsWario: &'a PedersenParams<'a>,
    s: BigNum,
    Cs: Commitment,
    P: EcPoint,
    Px: Commitment,
    Py: Commitment,
    secparam: usize,
    Q: Option<EcPoint>,
) {//-> ExpProof<'a> {
    let mut ctx = BigNumContext::new().unwrap();

    let mut alpha : Vec<BigNum> = Vec::with_capacity(secparam);
    let mut r : Vec<BigNum> = Vec::with_capacity(secparam);
    let mut T : Vec<EcPoint> = Vec::with_capacity(secparam);
    let mut A : Vec<EcPoint> = Vec::with_capacity(secparam);
    let mut Tx : Vec<Commitment> = Vec::with_capacity(secparam);
    let mut Ty : Vec<Commitment> = Vec::with_capacity(secparam);

    let mut NIST_order_curve = BigNum::new().unwrap();
    paramsNIST.c.order(&mut NIST_order_curve, &mut ctx).unwrap();
    

    for i in 0..secparam {
        // Generate random value
        let alpha_rand = generate_random(&NIST_order_curve).unwrap();
        alpha.push(alpha_rand.to_owned().unwrap());
        
        // Generate random value
        let r_rand = generate_random(&NIST_order_curve).unwrap();
        r.push(r_rand.to_owned().unwrap());
        
        let mut g_times_alpha_rand = EcPoint::new(&paramsNIST.c).unwrap();
        g_times_alpha_rand.mul_generator(&paramsNIST.c, &alpha_rand, &mut ctx);
        T.push(g_times_alpha_rand.to_owned(&paramsNIST.c).unwrap());

        //g_times_alpha_rand + r * h
        let mut r_h = EcPoint::new(&paramsNIST.c).unwrap();
        r_h.mul(&paramsNIST.c, &paramsNIST.h, &r_rand, &mut ctx);
        let mut g_alpha_plus_r_h = EcPoint::new(&paramsNIST.c).unwrap();
        g_alpha_plus_r_h.add(&paramsNIST.c, &g_times_alpha_rand, &r_h, &mut ctx);
        A.push(g_alpha_plus_r_h.to_owned(&paramsNIST.c).unwrap());

        // Build Tx and Ty
        let infinity_R = g_times_alpha_rand.is_infinity(&paramsNIST.c);
        assert!(!infinity_R, "g.alpha is at infinity");

        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
    
        g_times_alpha_rand.affine_coordinates_gfp(&paramsNIST.c, &mut x, &mut y, &mut ctx).unwrap();

        Tx.push(paramsWario.commit(&x));
        Ty.push(paramsWario.commit(&y));
    }

    // Compute challenge c = H (Cx, Cy, A, Tx, Ty)
    let mut arr : Vec<&EcPoint> = Vec::with_capacity(3*secparam+2);
    let mut groups : Vec<&EcGroupRef> = Vec::with_capacity(3*secparam+2);
    arr.push(&Px.p);
    groups.push(&paramsWario.c);
    arr.push(&Py.p);
    groups.push(&paramsWario.c);
    for i in 0..secparam {
        arr.push(&A[i]);
        groups.push(&paramsNIST.c);
        arr.push(&Tx[i].p);
        groups.push(&paramsWario.c);
        arr.push(&Ty[i].p);
        groups.push(&paramsWario.c);
    }
    let challenge = hash_points(MessageDigest::sha256(), &groups, &arr).unwrap();
    // NOTE: check that the challenge is done like this... Raise an issue tommorrow with a merge suggestion

    let mut all_proofs : Vec<ExpProof> = Vec::with_capacity(secparam);
    let mut proof : ExpProof;
    for i in 0..secparam {
        if challenge.is_bit_set(0)


    }

}


/* 
    const allProofs = new Array<ExpProof>(secparam)
    let proof: ExpProof
    for (let i = 0; i < secparam; i++) {
        if (isOdd(challenge)) {
            proof = new ExpProof(
                A[i as number],
                Tx[i as number].p,
                Ty[i as number].p,
                alpha[i as number],
                r[i as number],
                Tx[i as number].r,
                Ty[i as number].r,
                undefined,
                undefined,
                undefined,
                undefined,
                undefined
            )
        } else {
            // z = alpha - s
            const z = alpha[i as number].sub(paramsNIST.c.newScalar(s))
            let T1 = paramsNIST.g.mul(z)
            if (Q) {
                T1 = T1.add(Q)
            }
            const coordT1 = T1.toAffine()
            if (!coordT1) {
                throw new Error('T1 is at infinity')
            }
            const { x, y } = coordT1,
                T1x = paramsWario.commit(x),
                T1y = paramsWario.commit(y),
                // alpha R - s R = z R => T1 + P = T
                pointAddProof = await provePointAdd(
                    paramsWario,
                    T1,
                    P,
                    T[i as number],
                    T1x,
                    T1y,
                    Px,
                    Py,
                    Tx[i as number],
                    Ty[i as number]
                )

            proof = new ExpProof(
                A[i as number],
                Tx[i as number].p,
                Ty[i as number].p,
                undefined,
                undefined,
                undefined,
                undefined,
                z,
                r[i as number].sub(Cs.r),
                pointAddProof,
                T1x.r,
                T1y.r
            )
        }
        allProofs[i as number] = proof
        challenge >>= BigInt(1)
    }
    return allProofs
} */



