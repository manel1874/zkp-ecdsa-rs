use rand::{seq::SliceRandom, RngCore};
use rand::rngs::OsRng;

use openssl::hash::{hash, MessageDigest};
use openssl::ec::{EcGroup, EcGroupRef, EcPoint, PointConversionForm};
use openssl::bn::{BigNum, BigNumContext};

use crate::commit::pedersen::{Commitment, PedersenParams, generate_random};
use crate::exp::pointAdd::{PointAddProof, prove_point_add, aggregate_point_add};
use crate::equality::hash_points;
use crate::curves::multimult::{MultiMult, Relation};



pub struct ExpProof<'a> {
    pub groupNIST: &'a EcGroupRef,
    pub groupWario: &'a EcGroupRef,
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
        let c0 = self.a.eq(self.groupNIST, &other.a, &mut ctx).unwrap() &&
                self.t_x.eq(self.groupWario, &other.t_x, &mut ctx).unwrap() &&
                self.t_y.eq(self.groupWario, &other.t_y, &mut ctx).unwrap();
        
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

pub fn generate_indices(limit: usize) -> Vec<usize> {
    
    /*  We are not using the Algorithm P. The algorithm below is based on 
    Durstenfeld's algorithm for the [Fisher–Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm)

    Note: ret.slice(indnum) from typescript implementation does not have any effect.
    */

    let mut ret = (0..limit).collect::<Vec<usize>>();
    let mut rng = OsRng; // CSPRNG  

    ret.shuffle(&mut rng);

    ret
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
) -> Vec<ExpProof<'a>> {
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
    let mut challenge = hash_points(MessageDigest::sha256(), &groups, &arr).unwrap();

    let mut all_proofs : Vec<ExpProof> = Vec::with_capacity(secparam);
    let mut proof : ExpProof;
    for i in 0..secparam {
        if challenge.is_bit_set(0) {
            proof = ExpProof{
                groupNIST: paramsNIST.c,
                groupWario: paramsWario.c,
                a: A[i].to_owned(&paramsNIST.c).unwrap(),
                t_x: Tx[i].p.to_owned(&paramsWario.c).unwrap(),
                t_y: Ty[i].p.to_owned(&paramsWario.c).unwrap(),
                // Response 1
                alpha: Some(alpha[i].to_owned().unwrap()),
                beta1: Some(r[i].to_owned().unwrap()),
                beta2: Some(Tx[i].r.to_owned().unwrap()),
                beta3: Some(Ty[i].r.to_owned().unwrap()),
                // Response 2
                z: None,
                z2: None,
                proof: None,
                r1: None,
                r2: None,
            };
        } else {
            // z = alpha - s
            let mut z = BigNum::new().unwrap();

            let mut order_curve_wario = BigNum::new().unwrap();
            paramsWario.c.order(&mut order_curve_wario, &mut ctx).unwrap();
            let mut ss = BigNum::new().unwrap();
            ss.nnmod(&s, &order_curve_wario, &mut ctx).unwrap();

            //z.mod_sub(&alpha[i], &s, &order_curve_wario, &mut ctx).unwrap();
            z.checked_sub(&alpha[i], &ss).unwrap();

            // T1 = g.z
            let mut T1 = EcPoint::new(&paramsNIST.c).unwrap();
            T1.mul_generator(&paramsNIST.c, &z, &mut ctx);

            if Q.is_some() {
                let T1_int = T1.to_owned(&paramsNIST.c).unwrap();
                T1.add(&paramsNIST.c, &T1_int, &Q.as_ref().unwrap(), &mut ctx);
            }

            let infinity_T1 = T1.is_infinity(&paramsNIST.c);
            assert!(!infinity_T1, "T1 is at infinity");
    
            let mut x = BigNum::new().unwrap();
            let mut y = BigNum::new().unwrap();
        
            T1.affine_coordinates_gfp(&paramsNIST.c, &mut x, &mut y, &mut ctx).unwrap();

            let T1x = paramsWario.commit(&x);
            let T1y = paramsWario.commit(&y);
            // alpha R - s R = z R => T1 + P = T
            let pointAddProof = prove_point_add(
                paramsNIST,
                paramsWario,
                T1.to_owned(&paramsNIST.c).unwrap(),
                P.to_owned(&paramsNIST.c).unwrap(),
                T[i].to_owned(&paramsNIST.c).unwrap(),
                T1x.to_owned(),
                T1y.to_owned(),
                Px.to_owned(),
                Py.to_owned(),
                Tx[i].to_owned(),
                Ty[i].to_owned()
            );

            // z2 = r[i as number].sub(Cs.r)
            let mut z2 = BigNum::new().unwrap();
            //z2.mod_sub(&r[i], &Cs.r, &order_curve_wario, &mut ctx).unwrap();
            z2.checked_sub(&r[i], &Cs.r).unwrap();

            proof = ExpProof{
                groupNIST: paramsNIST.c,
                groupWario: paramsWario.c,
                a: A[i].to_owned(&paramsNIST.c).unwrap(),
                t_x: Tx[i].p.to_owned(&paramsWario.c).unwrap(),
                t_y: Ty[i].p.to_owned(&paramsWario.c).unwrap(),
                // Response 1
                alpha: None,
                beta1: None,
                beta2: None,
                beta3: None,
                // Response 2
                z: Some(z),
                z2: Some(z2),
                proof: Some(pointAddProof),
                r1: Some(T1x.r),
                r2: Some(T1y.r)
            };

        }

        all_proofs.push(proof);
        let challenge_int = challenge.to_owned().unwrap();
        challenge.rshift1(&challenge_int).unwrap();
    }

    all_proofs
}


pub fn verify_exp<'a>(
    paramsNIST: &'a PedersenParams<'a>,
    paramsWario: &'a PedersenParams<'a>,
    Clambda : EcPoint,
    Px: EcPoint,
    Py: EcPoint,
    pi: &'a Vec<ExpProof<'a>>,
    secparam: usize,
    Q: Option<EcPoint>,
) -> bool {
    let mut ctx = BigNumContext::new().unwrap();
    
    assert!(!(secparam > pi.len()), "security level not achieved");

    let mut multiW = MultiMult::new(&paramsWario.c);
    let mut multiN = MultiMult::new(&paramsNIST.c);

    multiW.add_known(paramsWario.g.to_owned(&paramsWario.c).unwrap());
    multiW.add_known(paramsWario.h.to_owned(&paramsWario.c).unwrap());
    multiN.add_known(paramsNIST.g.to_owned(&paramsWario.c).unwrap());
    multiN.add_known(paramsNIST.h.to_owned(&paramsWario.c).unwrap());
    multiN.add_known(Clambda.to_owned(&paramsWario.c).unwrap());

    // Compute challenge c = H (Cx, Cy, A, Tx, Ty)
    let mut arr : Vec<&EcPoint> = Vec::with_capacity(3*secparam+2);
    let mut groups : Vec<&EcGroupRef> = Vec::with_capacity(3*secparam+2);
    arr.push(&Px);
    groups.push(&paramsWario.c);
    arr.push(&Py);
    groups.push(&paramsWario.c);
    for i in 0..secparam {
        arr.push(&pi[i].a);
        groups.push(&paramsNIST.c);
        arr.push(&pi[i].t_x);
        groups.push(&paramsWario.c);
        arr.push(&pi[i].t_y);
        groups.push(&paramsWario.c);
    }
    let mut challenge = hash_points(MessageDigest::sha256(), &groups, &arr).unwrap();

    let indices = generate_indices(pi.len());
    let challenge_bits = padded_bits(&challenge, pi.len());

    for j in 0..secparam {
        let i = indices[j];

        if challenge_bits[i] {
            // Check the corresponding params are not set to None

            let params_not_found =  !(pi[i].alpha.is_some() &&
                pi[i].beta1.is_some() &&
                pi[i].beta2.is_some() &&
                pi[i].beta3.is_some());
            
            assert!(!params_not_found, "params not found");

            let alpha = pi[i].alpha.as_deref().unwrap();
            let beta1 = pi[i].beta1.as_deref().unwrap();
            let beta2 = pi[i].beta2.as_deref().unwrap();
            let beta3 = pi[i].beta3.as_deref().unwrap();
            let a = pi[i].a.as_ref();
            let t_x = pi[i].t_x.as_ref();
            let t_y = pi[i].t_y.as_ref();

            let mut T = EcPoint::new(&paramsNIST.c).unwrap();
            T.mul_generator(&paramsNIST.c, &alpha, &mut ctx);

            let mut relA = Relation::new(paramsNIST.c);

            // Compute -A
            let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
            let mut minus_a = EcPoint::new(&paramsNIST.c).unwrap();
            minus_a.mul(&paramsNIST.c, a, &minus_1, &mut ctx).unwrap();
            relA.insert_m(
                &[T.to_owned(&paramsNIST.c).unwrap(),
                paramsNIST.h.to_owned(&paramsNIST.c).unwrap(),
                minus_a],
                &[BigNum::from_u32(1).unwrap(),
                beta1.to_owned().unwrap(),
                BigNum::from_u32(1).unwrap()]);

            relA.drain(&mut multiN);

            // Build Tx and Ty
            let infinity_T = T.is_infinity(&paramsNIST.c);
            assert!(!infinity_T, "T is at infinity");

            let mut x = BigNum::new().unwrap();
            let mut y = BigNum::new().unwrap();
        
            T.affine_coordinates_gfp(&paramsNIST.c, &mut x, &mut y, &mut ctx).unwrap();

            let mut relTx = Relation::new(paramsWario.c); 
            let mut relTy = Relation::new(paramsWario.c); 

            // Compute -Tx
            let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
            let mut minus_t_x = EcPoint::new(&paramsNIST.c).unwrap();
            minus_t_x.mul(&paramsNIST.c, t_x, &minus_1, &mut ctx).unwrap();
            relTx.insert_m(
                &[paramsWario.g.to_owned(&paramsWario.c).unwrap(),
                paramsWario.h.to_owned(&paramsWario.c).unwrap(),
                minus_t_x],
                &[x,
                beta2.to_owned().unwrap(),
                BigNum::from_u32(1).unwrap()]);

            // Compute -Ty
            let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
            let mut minus_t_y = EcPoint::new(&paramsNIST.c).unwrap();
            minus_t_y.mul(&paramsNIST.c, t_y, &minus_1, &mut ctx).unwrap();
            relTx.insert_m(
                &[paramsWario.g.to_owned(&paramsWario.c).unwrap(),
                paramsWario.h.to_owned(&paramsWario.c).unwrap(),
                minus_t_y],
                &[y,
                beta3.to_owned().unwrap(),
                BigNum::from_u32(1).unwrap()]);

            relTx.drain(&mut multiW);
            relTy.drain(&mut multiW);
        } else {
            // Check the corresponding params are not set to NoneQ

            let params_not_found =  !(pi[i].z.is_some() &&
            pi[i].z2.is_some() &&
            pi[i].proof.is_some() &&
            pi[i].r1.is_some() &&
            pi[i].r2.is_some());
            
            assert!(!params_not_found, "params not found");

            let z = pi[i].z.as_deref().unwrap();
            let z2 = pi[i].z2.as_deref().unwrap();
            let r1 = pi[i].r1.as_deref().unwrap();
            let r2 = pi[i].r2.as_deref().unwrap();
            let a = pi[i].a.as_ref();
            let t_x = pi[i].t_x.as_ref();
            let t_y = pi[i].t_y.as_ref();

            let mut T1 = EcPoint::new(&paramsNIST.c).unwrap();
            T1.mul_generator(&paramsNIST.c, &z, &mut ctx);

            let mut relA = Relation::new(paramsNIST.c);

            // Compute -A
            let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
            let mut minus_a = EcPoint::new(&paramsNIST.c).unwrap();
            minus_a.mul(&paramsNIST.c, a, &minus_1, &mut ctx).unwrap();
            relA.insert_m(
                &[T1.to_owned(&paramsNIST.c).unwrap(),
                Clambda.to_owned(&paramsNIST.c).unwrap(),
                minus_a,
                paramsNIST.h.to_owned(&paramsNIST.c).unwrap()],
                &[BigNum::from_u32(1).unwrap(),
                BigNum::from_u32(1).unwrap(),
                BigNum::from_u32(1).unwrap(),
                z2.to_owned().unwrap()]);

            relA.drain(&mut multiN);

            if Q.is_some() {
                let T1_int = T1.to_owned(&paramsNIST.c).unwrap();
                T1.add(&paramsNIST.c, &T1_int, &Q.as_ref().unwrap(), &mut ctx);
            }

            let infinity_T1 = T1.is_infinity(&paramsNIST.c);
            assert!(!infinity_T1, "T1 is at infinity");
    
            let mut sx = BigNum::new().unwrap();
            let mut sy = BigNum::new().unwrap();
        
            T1.affine_coordinates_gfp(&paramsNIST.c, &mut sx, &mut sy, &mut ctx).unwrap();

            let mut T1x = EcPoint::new(&paramsWario.c).unwrap();
            let mut T1y = EcPoint::new(&paramsWario.c).unwrap();

            T1x.mul_full(&paramsWario.c, &sx, &paramsWario.h, &r1, &mut ctx);
            T1y.mul_full(&paramsWario.c, &sy, &paramsWario.h, &r2, &mut ctx);

            let ok = aggregate_point_add(
                paramsWario, 
                T1x, 
                T1y, 
                Px.to_owned(&paramsWario.c).unwrap(), 
                Py.to_owned(&paramsWario.c).unwrap(), 
                t_x.to_owned(&paramsWario.c).unwrap(), 
                t_y.to_owned(&paramsWario.c).unwrap(), 
                pi[i].proof.as_ref().unwrap(), 
                &mut multiW);

            if !ok {
                return false
            }
        }
    }

    return  multiW.evaluate().is_infinity(&paramsWario.c) && multiN.evaluate().is_infinity(&paramsNIST.c)
}

