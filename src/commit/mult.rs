use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};

use crate::commit::pedersen::{Commitment, PedersenParams, generate_random};
use crate::curves::multimult::{MultiMult, Relation};

use crate::equality::hash_points;

//#[derive(Serialize, Deserialize)]
pub struct MultProof<'a> {
    pub group: &'a EcGroupRef,
    pub c_4: EcPoint,
    pub a_x: EcPoint,
    pub a_y: EcPoint,
    pub a_z: EcPoint,
    pub a_4_1: EcPoint,
    pub a_4_2: EcPoint,
    pub t_x: BigNum,
    pub t_y: BigNum,
    pub t_z: BigNum,
    pub t_rx: BigNum,
    pub t_ry: BigNum,
    pub t_rz: BigNum,
    pub t_r4: BigNum,
}


impl<'a> MultProof<'a> {
    pub fn eq(&self, other: &MultProof) -> bool {
        
        let mut ctx = BigNumContext::new().unwrap();

        self.c_4.eq(self.group, &other.c_4, &mut ctx).unwrap() &&
        self.a_x.eq(self.group, &other.a_x, &mut ctx).unwrap() &&
        self.a_y.eq(self.group, &other.a_y, &mut ctx).unwrap() &&
        self.a_z.eq(self.group, &other.a_z, &mut ctx).unwrap() &&
        self.a_4_1.eq(self.group, &other.a_4_1, &mut ctx).unwrap() &&
        self.a_4_2.eq(self.group, &other.a_4_2, &mut ctx).unwrap() &&
        self.t_x == other.t_x &&
        self.t_y == other.t_y &&
        self.t_z == other.t_z &&
        self.t_rx == other.t_rx &&
        self.t_ry == other.t_ry &&
        self.t_rz == other.t_rz &&
        self.t_r4 == other.t_r4
    }
}


/*
 * Proof of multiplication
 * ZK(x, y, z, rx, ry, rz: z = x * y and Cx = xG + rx H and Cy = yG + ry H and Cz = zG + rz H)
 *    
 * params: PedersenParams,
 * x: bigint,
 * y: bigint,
 * z: bigint,
 * Cx: Commitment,
 * Cy: Commitment,
 * Cz: Commitment
 * 
 */

 
pub fn prov_mult<'a>(
    params: &'a PedersenParams<'a>,
    x: BigNum,
    y: BigNum,
    z: BigNum,
    Cx: Commitment,
    Cy: Commitment,
    Cz: Commitment
) -> MultProof<'a> {
    let mut ctx = BigNumContext::new().unwrap();

    // Take group order
    let mut order_curve = BigNum::new().unwrap();
    params.c.order(&mut order_curve, &mut ctx).unwrap();

    // Compute xx, C4 , r4
    // New scalar
    let mut xx = BigNum::new().unwrap();
    xx.nnmod(&x, &order_curve, &mut ctx).unwrap();

    let mut C4 = EcPoint::new(&params.c).unwrap();
    C4.mul(&params.c, &Cy.p, &xx, &mut ctx).unwrap(); // C4 = Cy * x
    
    let mut r4 = BigNum::new().unwrap();
    r4.mod_mul(&Cy.r, &xx, &order_curve, &mut ctx).unwrap(); // C4 = zG + r4H

    // Step 1: Compute commitments
    let k_x = generate_random(&order_curve).unwrap(); 
    let k_y = generate_random(&order_curve).unwrap(); 
    let k_z = generate_random(&order_curve).unwrap(); 

    let Ax = params.commit(&k_x);
    let Ay = params.commit(&k_y);
    let Az = params.commit(&k_z);

    let A4_1 = params.commit(&k_z); // TODO: check logic

    // New scalar
    let mut kx = BigNum::new().unwrap();
    kx.nnmod(&k_x, &order_curve, &mut ctx).unwrap();
    
    let mut A4_2 = EcPoint::new(&params.c).unwrap();
    A4_2.mul(&params.c, &Cy.p, &kx, &mut ctx).unwrap(); // C4 = Cy * kx
    
    // Step 2: Compute challenge  H(Cx, Cy, Cz, C4, Ax, Ay, Az, A4_1, A4_2)

    let c = hash_points(MessageDigest::sha256(), &[params.c], &[&Cx.p, &Cy.p, &Cz.p, &C4, &Ax.p, &Ay.p, &Az.p, &A4_1.p, &A4_2]).unwrap();
    
    // New scalar
    let mut cc = BigNum::new().unwrap();
    cc.nnmod(&c, &order_curve, &mut ctx).unwrap();
    let mut yy = BigNum::new().unwrap();
    yy.nnmod(&y, &order_curve, &mut ctx).unwrap();
    let mut zz = BigNum::new().unwrap();
    zz.nnmod(&z, &order_curve, &mut ctx).unwrap();
    // new scalar for ky and kz is missing
    //      ky = params.c.newScalar(k_y),
    //      kz = params.c.newScalar(k_z),

    // Compute tx = kx - c * x
    let mut cc_times_xx = BigNum::new().unwrap();
    cc_times_xx.mod_mul(&cc, &xx, &order_curve, &mut ctx).unwrap();
    let mut t_x = BigNum::new().unwrap();
    t_x.mod_sub(&kx, &cc_times_xx, &order_curve, &mut ctx).unwrap();

    // Compute ty = ky - c * y
    let mut cc_times_yy = BigNum::new().unwrap();
    cc_times_yy.mod_mul(&cc, &yy, &order_curve, &mut ctx).unwrap();
    let mut t_y = BigNum::new().unwrap();
    t_y.mod_sub(&k_y, &cc_times_yy, &order_curve, &mut ctx).unwrap();

    // Compute tz = kz - c * z
    let mut cc_times_zz = BigNum::new().unwrap();
    cc_times_zz.mod_mul(&cc, &zz, &order_curve, &mut ctx).unwrap();
    let mut t_z = BigNum::new().unwrap();
    t_z.mod_sub(&k_z, &cc_times_zz, &order_curve, &mut ctx).unwrap();

    // Compute t_rx = sx - c * rx
    let mut cc_times_rx = BigNum::new().unwrap();
    cc_times_rx.mod_mul(&cc, &Cx.r, &order_curve, &mut ctx).unwrap();   
    let mut t_rx = BigNum::new().unwrap();
    t_rx.mod_sub(&Ax.r, &cc_times_rx, &order_curve, &mut ctx).unwrap();
    
    // Compute t_ry = sy - c * ry
    let mut cc_times_ry = BigNum::new().unwrap();
    cc_times_ry.mod_mul(&cc, &Cy.r, &order_curve, &mut ctx).unwrap();   
    let mut t_ry = BigNum::new().unwrap();
    t_ry.mod_sub(&Ay.r, &cc_times_ry, &order_curve, &mut ctx).unwrap();

    // Compute t_rz = sz - c * rz
    let mut cc_times_rz = BigNum::new().unwrap();
    cc_times_rz.mod_mul(&cc, &Cz.r, &order_curve, &mut ctx).unwrap();   
    let mut t_rz = BigNum::new().unwrap();
    t_rz.mod_sub(&Az.r, &cc_times_rz, &order_curve, &mut ctx).unwrap();

    // Compute t_r4 = s4 - c * r4
    let mut cc_times_r4 = BigNum::new().unwrap();
    cc_times_r4.mod_mul(&cc, &r4, &order_curve, &mut ctx).unwrap();   
    let mut t_r4 = BigNum::new().unwrap();
    t_r4.mod_sub(&A4_1.r, &cc_times_r4, &order_curve, &mut ctx).unwrap();

    MultProof {
        group: params.c,
        c_4: C4,
        a_x: Ax.p,
        a_y: Ay.p,
        a_z: Az.p,
        a_4_1: A4_1.p,
        a_4_2: A4_2,
        t_x,
        t_y,
        t_z,
        t_rx,
        t_ry,
        t_rz,
        t_r4,
    }
}



pub fn verify_mult<'a>(
    params: &'a PedersenParams<'a>,
    Cx: EcPoint,
    Cy: EcPoint,
    Cz: EcPoint,
    pi: &'a MultProof<'a>
) -> bool {
    
    let mut multi = MultiMult::new(params.c);

    let ok = aggregate_mult(params, Cx, Cy, Cz, pi, &mut multi);

    if !ok {
        return false
    }
    
    multi.evaluate().is_infinity(&params.c)
}

pub fn aggregate_mult<'a> ( 
    params: &'a PedersenParams<'a>,
    Cx: EcPoint,
    Cy: EcPoint,
    Cz: EcPoint,
    pi: &'a MultProof<'a>,
    multi: &mut MultiMult
) -> bool {
    let mut ctx = BigNumContext::new().unwrap();

    // Compute scalar
    let challenge = hash_points(
        MessageDigest::sha256(), 
        &[params.c], 
        &[&Cx, &Cy, &Cz, &pi.c_4, &pi.a_x, &pi.a_y, &pi.a_z, &pi.a_4_1, &pi.a_4_2]).unwrap();
    // new scalar challenge
    let mut order_curve = BigNum::new().unwrap();
    params.c.order(&mut order_curve, &mut ctx).unwrap();
    let mut cc = BigNum::new().unwrap();
    cc.nnmod(&challenge, &order_curve, &mut ctx).unwrap();


    let mut A_xrel = Relation::new(params.c);
    // Compute -A_x
    let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
    let mut minus_a_x = EcPoint::new(&params.c).unwrap();
    minus_a_x.mul(&params.c, &pi.a_x, &minus_1, &mut ctx).unwrap();
    // insert several
    A_xrel.insert_m(
        &[params.g.to_owned(&params.c).unwrap(),
        params.h.to_owned(&params.c).unwrap(),
        Cx,
        minus_a_x],
        &[pi.t_x.to_owned().unwrap(),
        pi.t_rx.to_owned().unwrap(),
        cc.to_owned().unwrap(),
        BigNum::from_u32(1).unwrap()]);
    

    let mut A_yrel = Relation::new(params.c);
    // Compute -A_y
    let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
    let mut minus_a_y = EcPoint::new(&params.c).unwrap();
    minus_a_y.mul(&params.c, &pi.a_y, &minus_1, &mut ctx).unwrap();
    // insert several
    A_yrel.insert_m(
        &[params.g.to_owned(&params.c).unwrap(),
        params.h.to_owned(&params.c).unwrap(),
        Cy.to_owned(&params.c).unwrap(),
        minus_a_y],
        &[pi.t_y.to_owned().unwrap(),
        pi.t_ry.to_owned().unwrap(),
        cc.to_owned().unwrap(),
        BigNum::from_u32(1).unwrap()]);


    let mut A_zrel = Relation::new(params.c);
    // Compute -A_z
    let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
    let mut minus_a_z = EcPoint::new(&params.c).unwrap();
    minus_a_z.mul(&params.c, &pi.a_z, &minus_1, &mut ctx).unwrap();
    // insert several
    A_zrel.insert_m(
        &[params.g.to_owned(&params.c).unwrap(),
        params.h.to_owned(&params.c).unwrap(),
        Cz,
        minus_a_z],
        &[pi.t_z.to_owned().unwrap(),
        pi.t_rz.to_owned().unwrap(),
        cc.to_owned().unwrap(),
        BigNum::from_u32(1).unwrap()]);


    let mut A_4_1rel = Relation::new(params.c);
    // Compute -A_4_1
    let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
    let mut minus_a_4_1 = EcPoint::new(&params.c).unwrap();
    minus_a_4_1.mul(&params.c, &pi.a_4_1, &minus_1, &mut ctx).unwrap();
    // insert several
    A_4_1rel.insert_m(
        &[params.g.to_owned(&params.c).unwrap(),
        params.h.to_owned(&params.c).unwrap(),
        pi.c_4.to_owned(&params.c).unwrap(),
        minus_a_4_1],
        &[pi.t_z.to_owned().unwrap(),
        pi.t_r4.to_owned().unwrap(),
        cc.to_owned().unwrap(),
        BigNum::from_u32(1).unwrap()]);


    let mut A_4_2rel = Relation::new(params.c);
    // Compute -A_4_2
    let minus_1 = BigNum::from_dec_str("-1").unwrap(); 
    let mut minus_a_4_2 = EcPoint::new(&params.c).unwrap();
    minus_a_4_2.mul(&params.c, &pi.a_4_2, &minus_1, &mut ctx).unwrap();
    // insert several
    A_4_2rel.insert_m(
        &[Cy,
        pi.c_4.to_owned(&params.c).unwrap(),
        minus_a_4_2],
        &[pi.t_x.to_owned().unwrap(),
        cc.to_owned().unwrap(),
        BigNum::from_u32(1).unwrap()]);
    

    A_xrel.drain(multi);
    A_yrel.drain(multi);
    A_zrel.drain(multi);
    A_4_1rel.drain(multi);
    A_4_2rel.drain(multi);


    true

}

