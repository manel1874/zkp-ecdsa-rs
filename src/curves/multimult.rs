use std::cmp::Ordering;

use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::bn::{BigNum, BigNumContext};

use crate::commit::pedersen::generate_random;

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
    pub group: &'a EcGroupRef,
    pub pairs: Vec<Pair>,
    pub known: Vec<Ptidx>,
}



impl<'a> MultiMult<'a> {
    pub fn new(g: &'a EcGroupRef) -> Self {
        MultiMult {
            group: g,
            pairs: vec![],
            known: vec![],
        }
    }

    pub fn add_known(&mut self, pt: EcPoint) {
        
        is_compat_point(&pt, self.group);

        let mut ctx = BigNumContext::new().unwrap();
        
        let present = self.known.iter().any(|x| pt.eq(self.group, &x.pt, &mut ctx).unwrap());
        if !present {
            let new_scalar = BigNum::from_dec_str("0").unwrap();
            let new_pair = Pair::new( pt.to_owned(&self.group).unwrap(), new_scalar );
            let new_idx = self.pairs.len();

            self.pairs.push(new_pair);
            self.known.push(Ptidx { pt: pt.to_owned(&self.group).unwrap(), idx: new_idx });
        }
    }

    pub fn insert(&mut self, pt: EcPoint, s: BigNum) {
        
        is_compat_point(&pt, self.group);
        is_compat_scalar(&s, self.group);

        let mut ctx = BigNumContext::new().unwrap();

        if let Some(matched_idx) = self.known.iter().position(|x| pt.eq(self.group, &x.pt, &mut ctx).unwrap()) {
            
            let pairs_scalar = &self.pairs[matched_idx].scalar;
            let mut ps_sum_s = BigNum::new().unwrap();
            
            ps_sum_s.checked_add(&pairs_scalar, &s).unwrap();

            self.pairs[matched_idx].scalar = ps_sum_s;


        } else {
            self.pairs.push(Pair::new(pt, s));
        }


    }

    pub fn evaluate(&mut self) -> EcPoint {
        
        let mut ctx = BigNumContext::new().unwrap();
         
        if self.pairs.is_empty() {
            return EcPoint::new(&self.group).unwrap();
        }

        if self.pairs.len() == 1 {
            let a = &self.pairs[0];

            // Multiplies a.pt by a.scalar
            let mut apt_times_as = EcPoint::new(&self.group).unwrap();
            apt_times_as.mul(&self.group, &a.pt, &a.scalar, &mut ctx).unwrap();

            return apt_times_as;
        }

        heapify(&mut self.pairs);

        loop {
            if self.pairs.len() == 1 {
                let a = &self.pairs[0];
    
                // Multiplies a.pt by a.scalar
                let mut apt_times_as = EcPoint::new(&self.group).unwrap();
                apt_times_as.mul(&self.group, &a.pt, &a.scalar, &mut ctx).unwrap();
    
                return apt_times_as;
            }

            let a = extract_max(&mut self.pairs);
            
            let b = &self.pairs[0];

            
            // if b == 0
            if b.scalar.ucmp(&BigNum::from_u32(0).unwrap()) == Ordering::Equal {
                 
                // Multiplies a.pt by a.scalar
                let mut apt_times_as = EcPoint::new(&self.group).unwrap();
                apt_times_as.mul(&self.group, &a.pt, &a.scalar, &mut ctx).unwrap();
             
                return apt_times_as;
                
            }
            
             
            // c_scalar = a.s - b.s
            let mut c_scalar = BigNum::new().unwrap();
            c_scalar.checked_sub(&a.scalar, &b.scalar).unwrap();
            let c = Pair::new(a.pt.to_owned(&self.group).unwrap(), c_scalar); 

            // d_pt = b.pt + a.pt
            let mut d_pt = EcPoint::new(&self.group).unwrap();
            d_pt.add(&self.group, &b.pt, &a.pt, &mut ctx).unwrap();
            self.pairs[0].pt = d_pt;
            
            if c.scalar.ucmp(&BigNum::from_u32(0).unwrap()) != Ordering::Equal {
                self.pairs.push(c);
                let l = self.pairs.len();
                bubble_up(&mut self.pairs, l);
            }
            
        }

    }



}


fn extract_max<'a>(arr: &'a mut Vec<Pair>) -> Pair {
    // We shrink the heap
    
    let l = arr.len();
    arr.swap(0, l - 1);
   
    let max = arr.pop();
    match max {
        Some(max) => {
            push_down(arr, 1);
            max
        }
        None => panic!("heap underflow"),
    }
    
}


 
fn heapify(arr: &mut Vec<Pair>) {
    for i in 0..arr.len() {
        bubble_up(arr, i + 1);
    }
}


fn bubble_up(arr: &mut Vec<Pair>, index: usize) {
    // The indexing is easiest if 1 based
    if index == 0 || index == 1 {
        return;
    }
    let parent = index / 2;
    if arr[parent - 1].cmp(&arr[index - 1]) == Ordering::Less {
        arr.swap(parent - 1, index - 1);
        bubble_up(arr, parent);
    }
}


fn push_down(arr: &mut Vec<Pair>, parent: usize) {
    let son = 2 * parent;
    let daughter = 2 * parent + 1;
    // Checks if parent is a leaf
    if son > arr.len() {
        return;
    }
    // Compares son and daughter and assigns according to the following rule:
    //       let child = if (son > daughter) {son} else {daughter}
    let mut child = son;
    if daughter <= arr.len() {
        // Handle parents with one child
        if arr[daughter - 1].cmp(&arr[son - 1]) == Ordering::Greater {
            child = daughter;
        }
    }


    if arr[parent - 1].cmp(&arr[child - 1]) == Ordering::Less {
        arr.swap(parent - 1, child - 1);
        push_down(arr, child);
    }
}



pub struct Relation<'a> {
    pub group: &'a EcGroupRef,
    pairs: Vec<Pair>,
}

impl<'a> Relation<'a> {


    pub fn new(g: &'a EcGroupRef) -> Self {
        Relation { 
            group: g,
            pairs: vec![],
        }
    }

    
    pub fn insert_m(&mut self, pts: &[EcPoint], scalars: &[BigNum]) {
        if pts.len() != scalars.len() {
            panic!("arrays are not the same length");
        }
        for i in 0..pts.len() {
            self.insert(pts[i].to_owned(&self.group).unwrap(), scalars[i].to_owned().unwrap());
        }
    }
    

    pub fn insert(&mut self, pt: EcPoint, s: BigNum) {
        
        is_compat_point(&pt, self.group);
        is_compat_scalar(&s, self.group);

        self.pairs.push(Pair { pt, scalar: s });

    }
     
    pub fn drain(&self, m: &mut MultiMult) {
        
        let mut ctx = BigNumContext::new().unwrap();

        let mut order_curve = BigNum::new().unwrap();
        self.group.order(&mut order_curve, &mut ctx);
        let r = generate_random(&order_curve).unwrap();

        let l = self.pairs.len();
        
        for i in 0..l {

            let rel_pairs_i_pt = self.pairs[i].pt.to_owned(&self.group).unwrap();

            let mut rel_pairs_i_s_times_r = BigNum::new().unwrap();
            rel_pairs_i_s_times_r.checked_mul(&self.pairs[i].scalar, &r, &mut ctx).unwrap();

            m.insert( rel_pairs_i_pt, rel_pairs_i_s_times_r);
        }
    }
    
}



pub fn is_compat_point(pt: &EcPoint, g: &EcGroupRef) {
    // is compatible point

    let mut ctx = BigNumContext::new().unwrap();

    let compatible_point = pt.is_on_curve(g, &mut ctx).unwrap();
    assert!(!compatible_point, "point not compatible");
        
}

pub fn is_compat_scalar(s: &BigNum, g: &EcGroupRef) {
    // is compatible scalar

    let mut ctx = BigNumContext::new().unwrap();

    let mut order_curve = BigNum::new().unwrap();
    g.order(&mut order_curve, &mut ctx);
    let compatible_scalar = s <= &order_curve;
    assert!(!compatible_scalar, "scalar not compatible");
}


