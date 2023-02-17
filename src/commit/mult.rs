use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::bn::{BigNum, BigNumRef, BigNumContext, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};

use crate::commit::pedersen::{Commitment, PedersenParams, generate_random};
use crate::curves::multimult::{MultiMult, Relation};


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
    fn eq(&self, other: &MultProof) -> bool {
        
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
) {//-> MultProof {
    let mut ctx = BigNumContext::new().unwrap();

    // Take group order
    let mut order_curve = BigNum::new().unwrap();
    params.c.order(&mut order_curve, &mut ctx).unwrap();

    // Compute xx, C4 , r4
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

    let mut kx = BigNum::new().unwrap();
    kx.nnmod(&k_x, &order_curve, &mut ctx).unwrap();
    
    let mut A4_2 = EcPoint::new(&params.c).unwrap();
    A4_2.mul(&params.c, &Cy.p, &kx, &mut ctx).unwrap(); // C4 = Cy * kx
    
    // Step 2: Compute challenge  H(Cx, Cy, Cz, C4, Ax, Ay, Az, A4_1, A4_2)

    let c = hash_points(MessageDigest::sha256(), params.c, &[&Cx.p, &Cy.p, &A1.p, &A2.p]).unwrap();



/* 

    
    const xx = params.c.newScalar(x),
        C4 = Cy.p.mul(xx), // C4 = Cy * x
        r4 = Cy.r.mul(xx), // C4 = zG + r4H
        // Step 1: Compute commitments
        k_x = rnd(params.c.order),
        k_y = rnd(params.c.order),
        k_z = rnd(params.c.order),
        kx = params.c.newScalar(k_x),
        Ax = params.commit(k_x),
        Ay = params.commit(k_y),
        Az = params.commit(k_z),
        A4_1 = params.commit(k_z),
        A4_2 = Cy.p.mul(kx),
        // Step 2: Compute challenge  H(Cx, Cy, Cz, C4, Ax, Ay, Az, A4_1, A4_2)
        c = await hashPoints(SHA-256, [Cx.p, Cy.p, Cz.p, C4, Ax.p, Ay.p, Az.p, A4_1.p, A4_2]),
        cc = params.c.newScalar(c),
        ky = params.c.newScalar(k_y),
        kz = params.c.newScalar(k_z),
        yy = params.c.newScalar(y),
        zz = params.c.newScalar(z),
        t_x = kx.sub(cc.mul(xx)), // tx = kx-c*x
        t_y = ky.sub(cc.mul(yy)), // ty = ky-c*y
        t_z = kz.sub(cc.mul(zz)), // tz = kz-c*z
        t_rx = Ax.r.sub(cc.mul(Cx.r)), //  t_rx = sx-c*rx
        t_ry = Ay.r.sub(cc.mul(Cy.r)), //  t_ry = sy-c*ry
        t_rz = Az.r.sub(cc.mul(Cz.r)), //  t_rz = sz-c*rz
        t_r4 = A4_1.r.sub(cc.mul(r4)) //  t_r4 = s4-c*r4

    return new MultProof(C4, Ax.p, Ay.p, Az.p, A4_1.p, A4_2, t_x, t_y, t_z, t_rx, t_ry, t_rz, t_r4)
*/
}

