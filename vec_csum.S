//------------------------------------------------------------------
// file:  vec_csum.S
//    AltiVec enabled version of linux' checksum routines
//------------------------------------------------------------------

//------------------------------------------------------------------
//	Copyright Motorola, Inc. 2003
//	ALL RIGHTS RESERVED
//
//	You are hereby granted a copyright license to use, modify, and 
//	distribute the SOFTWARE so long as this entire notice is retained 
//	without alteration in any modified and/or redistributed versions, 
//	and that such modified versions are clearly identified as such.  
//	No licenses are granted by implication, estoppel or otherwise under 
//	any patents or trademarks of Motorola, Inc.
//
//	The SOFTWARE is provided on an "AS IS" basis and without warranty.  
//	To the maximum extent permitted by applicable law, MOTOROLA DISCLAIMS 
//	ALL WARRANTIES WHETHER EXPRESS OR IMPLIED, INCLUDING IMPLIED 
//	WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR 
//	PURPOSE AND ANY WARRANTY AGAINST INFRINGEMENT WITH 
//	REGARD TO THE SOFTWARE (INCLUDING ANY MODIFIED VERSIONS 
//	THEREOF) AND ANY ACCOMPANYING WRITTEN MATERIALS. 
//
//	To the maximum extent permitted by applicable law, IN NO EVENT SHALL 
//	MOTOROLA BE LIABLE FOR ANY DAMAGES WHATSOEVER 
//	(INCLUDING WITHOUT LIMITATION, DAMAGES FOR LOSS OF 
//	BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS 
//	INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OF THE USE OR 
//	INABILITY TO USE THE SOFTWARE.   Motorola assumes no responsibility 
//	for the maintenance and support of the SOFTWARE.
//------------------------------------------------------------------

//------------------------------------------------------------------
// extern  unsigned long csum_partial_copy_generic(src, dst, len, sum,
//                                                  src_err, dst_err);
// Computes the checksum of a memory block at src, length len,
// and adds in "sum" (32-bit), while copying the block to dst.
// Returns:
//  unsigned long sum
//------------------------------------------------------------------

//------------------------------------------------------------------
// extern  unsigned long csum_partial(buff, len, sum);
//
// computes the checksum of a memory block at buff, length len,
// and adds in "sum" (32-bit unsigned long)
// Returns:
//  unsigned long sum
//------------------------------------------------------------------

//------------------------------------------------------------------
// Assumptions from studying the original linux code:
//   Copying forward is always safe
//   src and dst are always half-word aligned
//   len may be odd or even 0-n;
//   there is no test to see if src and dst are equal.
//   returns unsigned int checksum
//
//------------------------------------------------------------------

// Revision History:
//    Rev 0.0	Original                          Chuck Corley	04/19/03
//
//  This is alpha quality code; users are encouraged to make it faster.
//  ASSUMPTIONS:
//     Code is highly likely to be in the cache; data is not (streaming data)

#ifdef __ppc__

// Don't use vectors for BC <= MIN_VEC. Works only if MIN_VEC >= 32 bytes.
#define MIN_VEC 48	// Experimentally chosen on 7455@1GHz/133 to beat scalar

 // Register useage
#define Rt r0	// 	r0 when used as a temporary register	

#define SRC r3	// 	entering: src ptr; exiting: unsigned long checksum

#define DST r4	// 	entering: dst pointer; exiting: 

#define BC r5	//	entering: Byte_Count

#define SUM r6	//	entering: Partial checksum

#define SER r7	//	entering: src_err address

#define DER r8	//	entering: dst_err address

#define DM2 r9//	dst -2 for hw-by-hw forwards initially
#define D r9	//	dst[28:31]
#define DR r9	//	dst[0:27]
#define DNX r9	//	(dst+n*16)[28:31]
#define BL r9	//	second byte_kount index pointer

#define DBC r10//	dst + byte count initially
#define DBK r10//	(dst+byte_count-1) then (dst+byte_count-1)[28:31]

#define SM2 r11//	src -2 for hw-by-hw forwards initially
#define QW r11	//  	number of quad words (vectors)
#define SP8 r11	//	data stream touch block & stride info for Big_loop
#define SBC r11//	src + byte count initially then src[28:31]

#define BK r12	//  	Byte Kount index
#define BLK r12	//      temporary data stream touch block & stride info
#define S r12//	src[28:31]
#define DMS r12	//      dst - src initially

#define V0	v0	// 	all zeros
#define VCARS	v0 	//	sum of carries

#define V1	v1	// 	all ones
#define VMM	v1	// 	mask for final dst right

#define VS0	v2	//  	src vector for permuting
#define VL	v2	//	low data	

#define VS1	v3	//  	src vector for permuting
#define VH 	v3	//	high data

#define VPS0	v4	// 	permuted source vector to store

#define VP2	v5	// 	dst permute register
#define VM	v5	// 	mask for first dst left
#define VS2	v5	//  	src vector for permuting

#define VP3	v6	// 	d - s permute register
#define VS3	v6	// 	4th src vector in csum_partial

#define VP4	v7	// 	Byte_Count permute register
#define VPS1	v7	//  	2nd permuted source vector to store

#define VSUM 	v8	//	Updated sum
#define VFIN 	v8	//	final sum

#define VCAR1 	v9 	//	temp register for carries
#define VCAR3 	v9 	//	temp register for carries

#define VCAR2 	v10 	//	temp register for carries

#define VCARF 	v11 	//	temp register for carries

#define	VTEMP 	v12 	//	Temp register

#define SP r1

// Conditionalize the use of dcba.  It will help if the data is
// not in cache and hurt if it is.  Generally, except for small
// benchmarks repeated many times, we assume data is not in cache
// (data streaming) and using dcba is a performance boost.
#ifndef NO_DCBA
#if defined(__GNUC__) || defined(__MWERKS__) || defined(_DIAB_TOOL)
 // gcc and codewarrior and diab don't assemble dcba
#define DCBK .long 0x7c0465ec
// dcba r4,r12    or    dcba DST,BK
#else
#ifdef __ghs__
.macro DCBK
.long 0x7c0465ec
.endm
#else
#define DCBK dcba DST,BK
#endif  // __ghs__
#endif  // __GNUC__ or __MWERKS__
#else
#define DCBK nop
#endif  // NO_DCBA

// Conditionalize the use of dst (data stream touch).  It will help
// if the data is not in cache and hurt if it is (though not as badly
// as dcbz).  Generally, except for small benchmarks repeated many times,
// we assume data is not in cache (data streaming) and using dst is a
// performance boost.
#ifndef NO_DST
#define STRM_F dst	SRC,BLK,0
#define STRM_1 dst	SP8,Rt,1

#else
#define STRM_F	nop
#define STRM_1	nop
#endif
	.text
#if __MWERKS__
	.align	16
#else
	.align	4
#endif

#ifdef LIBMOTOVEC
	.globl	_csum_partial_copy_generic_vec     
_csum_partial_copy_generic:
#else
	.globl	_vec_csum_partial_copy_generic     
_vec_csum_partial_copy_generic:
#endif

	li	BK,32		// IU1 
	rlwinm	Rt,BC,31,1,31	// IU1 BC/2
	cmpi	cr7,0,BC,MIN_VEC	// IU1 Check for minimum byte count

	dcbt	SRC,BK		// LSU prefetch next cacheline
	cmpi	cr6,0,Rt,0	// IU1 BC/2 == 0?
	addic	SUM,SUM,0	// IU1 Zero carry bit

	addi	SM2,SRC,-2	// IU1 Pre-bias and duplicate src
	add	DBC,DST,BC	// IU1 Address of last dst byte + 1
	bgt	cr7,v_csumcpy	// b if BC>MIN_VEC (will copy vectors fwd)
	andi.	BK,BC,1		// IU1 BC[31]==0?

	addi	DM2,DST,-2	// IU1 Pre-bias and duplicate destination
	add	S,SRC,BC	// IU1 Last src byte + 1 (temp use of S)
	beq	cr6,No_HWs	// b if BC/2==0
	mtctr	Rt		// i=BC/2; do ...;i--; while (i>0)
HW_cpy:
	lhzu	Rt,2(SM2)	// LSU
	sthu	Rt,2(DM2)	// LSU
	addc	SUM,SUM,Rt	// IU1
	bdnz	HW_cpy
No_HWs:
	beq	BC_even		// b if BC[31]==0 (or DBC[31]==0 when aligned)
	lbz	Rt,-1(S)	// LSU Get last src address byte

	stb	Rt,-1(DBC)	// LSU Store to last dst address byte
	rlwinm	Rt,Rt,8,16,23	// IU1 Shift odd byte left

	addc	SUM,SUM,Rt	// IU1
BC_even:
	addze	SRC,SUM
	blr

v_csumcpy:
	lvsr	VP2,0,DST	// LSU Permute vector for initial byte mask
	rlwinm	D,DST,0,28,31	// IU1 D = dst[28:31]
	rlwinm	S,SRC,0,28,31	// IU1 Save src address bits s[28:31]

	lvsr	VP4,DST,BC	// LSU Permute vector for final byte mask
	subf.	S,S,D		// IU1 if D-S<0 essentially shifting left
	subf	DMS,SRC,DST	// IU1 Compute dst-src difference

	lvsr	VP3,0,DMS	// LSU Permute vector for dst - src shft right
	li	BK,64		// IU1 Index of next cache line
	vxor	V0,V0,V0	// VIU Clear v0

	dcbt	SRC,BK		// LSU Prefetch next cache line at src+64
	cmpi	cr1,0,D,0	// IU1 Is D0 left justified?
	vnor	V1,V0,V0	// VIU1 Create a vector of all ones

	addi	DR,DST,16	// IU1 Address of second dst vector
	addi	DBK,DBC,-1	// IU1 Address of last dst byte
	vperm	VM,V1,V0,VP2	// VPU D0 select vector for dst left; src right	
	bge	Ld_bytes_rt	// b if shifting right (D-S>=0)

	lvx	VS0,0,SRC	// LSU Get S0 load started
	addi	SRC,SRC,16	// IU1 Increment src base (to keep BK useful)

Ld_bytes_rt:	// Come here to get VS1 & Don't care what VS0 is	
	lvx	VS1,0,SRC	// LSU Get S1 (or S0 if D-S>=0) in upper vector
	rlwinm	DR,DR,0,0,27	// IU1 (DST+16)[0:27]

	vperm	VMM,V0,V1,VP4   // VPU DN select vector for src left; dst right 
	subf	QW,DR,DBK	// IU1 Bytes of full vectors to move (-16)
	vxor	VPS1,VPS1,VPS1	// VIU Clear VPS1
	
	vxor	VCARF,VCARF,VCARF	//VIU1 clear VCARF
	rlwinm	QW,QW,28,4,31	// IU1 Quad words remaining
	rlwinm	Rt,DBK,0,28,31	// IU1 (DBK = DST+BC-1)[28:31]

	li	BK,96		// IU1 Index of next cache line
	cmpi	cr5,0,Rt,0xF	// IU1 Is DN right justified?
	subf	Rt,DST,DR	// IU1 How many bytes in first destination?

	mtctr	QW		// IU2
	cmpi	cr6,0,QW,4	// IU1 Check QW>4
	mtcrf	0x01,Rt		// IU2 Put bytes in 1st dst in cr7

	vperm	VPS0,VS0,VS1,VP3	// VPU Align S0 and S1 to D0
	vor	VS0,VS1,VS1	// VIU1 Move upper vector to lower
	dcbt	SRC,BK		// LSU Prefetch next cache line at src+96
	beq	cr1,Left_just	// b if D0 is left justified

	li	BK,0		// IU1 Initialize byte kount index
	vsel	VPS0,VPS0,V0,VM	// VIU1 Select zeroes left | S0 bytes right
	bns	cr7,No_B_fwd	// b if only even number of bytes to store

	stvebx	VPS0,DST,BK	// LSU store first byte at DST+0
	addi	BK,BK,1		// IU1 increment index
No_B_fwd:
	bne	cr7,No_H_fwd	// b if only words to store

	stvehx	VPS0,DST,BK	// LSU store halfword at DST+0/1
	addi	BK,BK,2		// IU1 increment index
No_H_fwd:
	bng	cr7,No_W1_fwd	// b if exactly zero or two words to store

	stvewx	VPS0,DST,BK	// LSU store word 1 of one or three
	addi	BK,BK,4		// IU1 increment index

No_W1_fwd:
	bnl	cr7,No_W2_fwd	// b if there was only one word to store
	stvewx	VPS0,DST,BK	// LSU store word 1 of two or 2 of three
	addi	BK,BK,4		// IU1 increment index

	stvewx	VPS0,DST,BK	// LSU store word 2 of two or 3 of three
	b	No_W2_fwd

Left_just:	
	stvx	VPS0,0,DST	// LSU Store 16 bytes at D0
No_W2_fwd:
	vxor	VSUM,VSUM,VSUM	// VIU1 Clear VSUM
	li	BK,16		// IU1 Re-initialize byte kount index

QW_fwd_loop:
	lvx	VS1,SRC,BK	// LSU Get S2 (or S1)
	vaddcuw	VCAR1,VPS0,VSUM	// VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VPS0,VSUM	// VIU1 data + previous sum (no carries)

	vperm	VPS0,VS0,VS1,VP3	// VPU Align S1 and S2 to D1
	vor	VS0,VS1,VS1	// VIU1 Move upper vector to lower

	stvx	VPS0,DST,BK	// LSU Store 16 bytes at D1(+n*16 where n<4)
	vadduwm	VCARF,VCAR1,VCARF	// VIU1 Update VCARF
	addi	BK,BK,16	// IU1 Increment byte kount index
	bdnzf	25,QW_fwd_loop	// b if 4 or less quad words to do

	add	DNX,DST,BK	// IU1 address of next store (DST+32 if QW>4)
	addi	QW,QW,-1	// IU1 One more QW stored by now
	bgt	cr6,GT_4QW_fwd	// b if >4 quad words left

Last_ld_fwd:	// Next 16 bytes is the last; we're done.
	add	DBC,DST,BC	// IU1 Recompute address of last dst byte + 1
	add	SBC,SRC,BC	// IU1 Recompute address of last src byte + 1
	bge	No_ld_fwd	// b if shifting right (D-S>=0)

	addi	SBC,SBC,-16	// IU1 if D-S>=0 we didn't add 16 to src
No_ld_fwd:
	mtcrf	0x01,DBC	// IU2 Put final vector byte count in cr7
	addi	Rt,SBC,-1	// IU1 Recompute address of last src byte

	lvx	VS1,0,Rt	// LSU Get last source S14 (guaranteed SN)
	vaddcuw	VCAR1,VPS0,VSUM	// VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VPS0,VSUM	// VIU1 data + previous sum (no carries)

	vadduwm	VCARF,VCAR1,VCARF	// VIU1 Update VCARF

	vperm	VPS0,VS0,VS1,VP3	// VPU Align S13 and S14 to D14
	beq	cr5,Rt_just_fwd	// b if last destination is right justified
	vsel	VPS0,VPS0,V0,VMM   // VIU1 Select src bytes left | zeroes right

	rlwinm	DBK,DBK,0,0,27	// IU1 Round to QW addr of last byte
	li	D,0		// IU1 Initialize index pointer
	bnl	cr7,Only_1W_fwd	// b if there was only one or zero words to store

	stvewx	VPS0,DBK,D	// LSU store word 1 of two or three
	addi	D,D,4		// IU1 increment index

	stvewx	VPS0,DBK,D	// LSU store word 2 of two or three
	addi	D,D,4		// IU1 increment index
Only_1W_fwd:
	bng	cr7,Only_2W_fwd	// b if there were only two or zero words to store

	stvewx	VPS0,DBK,D	// LSU store word 3 of three if necessary
	addi	D,D,4		// IU1 increment index
Only_2W_fwd:
	bne	cr7,Only_B_fwd	// b if there are no half words to store

	stvehx	VPS0,DBK,D	// LSU store one halfword if necessary
	addi	D,D,2		// IU1 increment index
Only_B_fwd:
	bns	cr7,All_done_fwd	// b if there are no bytes to store

	stvebx	VPS0,DBK,D	// LSU store one byte if necessary
	b	All_done_fwd

Rt_just_fwd:
	stvx	VPS0,DST,BK	// LSU Store 16 bytes at D14
All_done_fwd:
	vaddcuw	VCAR1,VPS0,VPS1	//VIU1 add data and store carries

	vadduwm	VTEMP,VPS0,VPS1	//VIU1 add data (no carries)

	vaddcuw	VCAR2,VTEMP,VSUM	//VIU1 data + previous sum ->store carries
	
	vadduwm	VSUM,VTEMP,VSUM	//VIU1	data + previous sum
	
	vadduwm	VCAR3,VCAR1,VCAR2	//VIU1 add carries from previous adds
	vmrglh	VL,V0,VSUM	// VPU separate low shorts of sum

	vadduwm	VCARF,VCAR3,VCARF	//VIU1 update VCARF
	vmrghh	VH,V0,VSUM	//VPU separate high shorts of sum
	rlwinm	DBK,SP,0,0,27	// IU1 Align stack pointer to QW

	vsumsws	VCARS,VCARF,V0	 //VIU2 sum all carries 
	vadduwm	VSUM,VL,VH	//VIU1 add low and high data
	li	BK,-16		// IU1 Index 0x10 less than SP

	vsumsws	VFIN,VSUM,VCARS	//VIU2	sum all data including carries
        	
	stvx	VFIN,DBK,BK	// LSU Store partial checksum from VR
	
	lwz	SRC,-4(DBK)	// LSU Load partial checksum to GPR

	addc	SRC,SRC,SUM

	addze	SRC,SRC

	blr			// Return destination address from entry
	

#ifdef __MWERKS__
	.align	16
#else
	.align	4
#endif
GT_4QW_fwd:	// Do once if nxt st is to odd half of cache line, else twice

	lvx	VS1,SRC,BK	// LSU Get S3 (or S2)
	addi	QW,QW,-1	// IU1 Keeping track of QWs stored
	vaddcuw	VCAR1,VPS0,VSUM	// VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VPS0,VSUM	// VIU1 data + previous sum (no carries)
	mtcrf	0x02,DNX	// IU2 cr6[3]=((DST+32)[27]==1)?1:0;
	addi	DNX,DNX,16		// IU1 Update cr6 for next loop

	addi	Rt,QW,-2	// IU1 Insure at least 2 QW left after big loop
	vperm	VPS0,VS0,VS1,VP3	// VPU Align S2 and S3 to D2
	vor	VS0,VS1,VS1	// VIU1 Move upper vector to lower

	stvx	VPS0,DST,BK	// LSU Store 16 bytes at D2
	addi	BK,BK,16	// IU1 Increment byte count by 16
	vadduwm	VCARF,VCAR1,VCARF	// VIU1 Update VCARF
	bdnzf	27,GT_4QW_fwd	// b if next store is to lower (even) half of CL
// At this point next store will be to even address.

	mtcrf	0x02,DBK	// IU2 cr6[3]=((last store)[27]==1)?1:0; (odd?)
	addi	SP8,SRC,96	// IU1 Starting address for dcbt
	addi	BL,BK,16	// IU1 Create an alternate byte kount + 32

// We need the ctr register to reflect an even byte count before entering
// the next block - faster to decrement than to reload.

	bns	cr6,B32_fwd	// b if DST[27] == 0; i.e, final store is even

	bdnz	B32_fwd		// decrement counter for last QW store odd

B32_fwd:	// Should be at least 2 stores remaining and next 2 are cache aligned
	lvx	VS1,SRC,BK	// LSU Get S4
	addi	SP8,SP8,32	// IU1 Next starting address for dcbt
	vaddcuw	VCAR1,VPS0,VPS1	// VIU1 add data and store carries

	lvx	VS2,SRC,BL	// LSU Get S5
	vadduwm	VTEMP,VPS0,VPS1	// VIU1 add data (no carries)

	dcbt	0,SP8		// LSU Prefetch cache line 64 bytes ahead
	vaddcuw	VCAR2,VTEMP,VSUM //VIU1 data + previous sum ->store carries

	DCBK			// LSU Kill instead of RWITM
	vadduwm	VSUM,VTEMP,VSUM //VIU1	data + previous sum
	vperm	VPS1,VS0,VS1,VP3	// VPU Align S11 and S12 to D11

	stvx	VPS1,DST,BK	// LSU Store 16 bytes at D11
	vperm	VPS0,VS1,VS2,VP3	// VPU Align S12 and S13 to D12
	vadduwm	VCAR3,VCAR1,VCAR2 //VIU1 add carries from previous adds
	bdz	Nxt_loc_fwd	// always decrement and branch to next instr		

Nxt_loc_fwd:
	stvx	VPS0,DST,BL	// LSU Store 16 bytes at D12
	vor	VS0,VS2,VS2	// VIU1 Move S13 to S11
	vadduwm	VCARF,VCAR3,VCARF //VIU1 update VCARF

	addi	BK,BL,16	// IU1 Increment byte count
	addi	BL,BK,16	// IU1 Increment alternate byte count
	bdnz	B32_fwd		// b if there are at least two more QWs to do

	bso	cr6,One_even_QW	// b if there is one even and one odd QW to store

	b	Last_ld_fwd	// b if last store is to even address

// Come here with two more loads and two stores to do
One_even_QW:
	lvx	VS1,SRC,BK	// LSU Get S6 (or S5 if if D-S>=0)
	vaddcuw	VCAR1,VPS0,VSUM	// VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VPS0,VSUM	// VIU1 data + previous sum (no carries)

	vadduwm	VCARF,VCAR1,VCARF	// VIU1 Update VCARF

	vperm	VPS0,VS0,VS1,VP3	// VPU Align S13 and S14 to D13
	vor	VS0,VS1,VS1	// VIU1 Move upper vector to lower

	stvx	VPS0,DST,BK	// LSU Store 16 bytes at D13
	addi	BK,BK,16	// IU1 Increment byte count
	b	Last_ld_fwd

// End of vec_csum_partial_copy_generic in AltiVec

// Modified from above Register useage
// Don't use vectors for BC <= MIN_VEC_CS. Works only if MIN_VEC >= 32 bytes.
#define MIN_VEC_CS 48	// Chosen experimentally on MPC7455@1GHz/133MHz bus
#undef	DST	//      will not be using here
#undef	BC
#define BC r4	//	entering: Byte_Count

#undef	SUM
#define SUM r5	//	entering: Partial checksum

#if __MWERKS__
	.align	16
#else
	.align	4
#endif
#ifdef LIBMOTOVEC
	.globl	_csum_partial_vec     
_csum_partial:
#else
	.globl	_vec_csum_partial 
_vec_csum_partial:
#endif
	li	BK,32		// IU1 
	rlwinm	Rt,BC,31,1,31	// IU1 BC/2
	cmpi	cr7,0,BC,MIN_VEC_CS	// IU1 Check for minimum byte count

	dcbt	SRC,BK		// LSU prefetch next cacheline
	cmpi	cr6,0,Rt,0	// IU1 BC/2 == 0?
	addic	SUM,SUM,0	// IU1 Zero carry bit

	addi	SM2,SRC,-2	// IU1 Pre-bias and duplicate src
	add	DBC,SRC,BC	// IU1 Compute address of last src byte + 1
	bgt	cr7,v_csum	// b if BC>MIN_VEC_CS
	andi.	BK,BC,1		// IU1 BC[31]==0?

	beq	cr6,No_HWs_cs	// b if BC/2==0
	mtctr	Rt		// i=BC/2; do ...;i--; while (i>0)
HW_cs:
	lhzu	Rt,2(SM2)	// LSU

	addc	SUM,SUM,Rt	// IU1
	bdnz	HW_cs
No_HWs_cs:
	beq	BC_even_cs	// b if BC[31]==0 (or DBC[31]==0 when aligned)
	lbz	Rt,-1(DBC)	// LSU Get last src address byte

	rlwinm	Rt,Rt,8,16,23	// IU1 Shift odd byte left

	addc	SUM,SUM,Rt	// IU1
BC_even_cs:
	addze	SRC,SUM
	blr

v_csum:
	lvsr	VP2,0,SRC	// LSU Permute vector for initial byte mask
	addi	DR,SRC,16	// IU1 Address of second src vector
	li	BK,64		// IU1 Index of next cache line

	lvsr	VP4,SRC,BC	// LSU Permute vector for final byte mask
	rlwinm	DR,DR,0,0,27	// IU1 (DST+16)[0:27]
	addi	DBK,DBC,-1	// IU1 Address of last src byte

	lvx	VS0,0,SRC	// LSU Get S0 load started
	subf	QW,DR,DBK	// IU1 Bytes of full vectors to test (-16)
	vxor	V0,V0,V0	// VIU Clear v0

	dcbt	SRC,BK		// LSU Prefetch next cache line at src+64
	rlwinm	QW,QW,28,4,31	// IU1 Quad words remaining
	vnor	V1,V0,V0	// VIU1 Create a vector of all ones

	mtctr	QW		// IU2
	vxor	VCARF,VCARF,VCARF	//VIU1 clear VCARF
	vperm	VM,V1,V0,VP2	// VPU D0 select vector for dst left; src right	

	cmpi	cr6,0,QW,4	// IU1 Check QW>4
	vxor	VSUM,VSUM,VSUM	// VIU1 Clear VSUM
	vperm	VMM,V0,V1,VP4   // VPU DN select vector for src left; dst right 

	li	BK,16		// IU1 Initialize byte kount index
	vsel	VS0,VS0,V0,VM	// VIU1 Select zeroes left | S0 bytes right
vp_fwd_loop:
	lvx	VS1,SRC,BK	// LSU Get S1
	vaddcuw	VCAR1,VS0,VSUM	// VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VS0,VSUM	// VIU1 data + previous sum (no carries)

	vadduwm	VCARF,VCAR1,VCARF	// VIU1 Update VCARF
	addi	BK,BK,16	// IU1 Increment byte kount index

	vor	VS0,VS1,VS1	// VIU1 Swap vectors for next loop
	bdnzf	25,vp_fwd_loop	// b if 4 or less quad words to do

	add	DNX,SRC,BK	// IU1 address of next load (SRC+32 if QW>4)
	addi	QW,QW,-1	// IU1 One more QW summed by now
	bgt	cr6,GT_4QW_cs	// b if >4 quad words left
	vxor	VS1,VS1,VS1	// VIU1 Zero before adding below

// Next 16 bytes is the last; we're done.
Last_ld_cs:
	lvx	VS2,0,DBK	// LSU Get last source (guaranteed SN)
	vaddcuw	VCAR1,VS0,VS1	// VIU1 add data and store carries
	rlwinm	DBK,DBK,0,28,31 // IU1 (dst + BC -1)[28:31]

	vadduwm	VTEMP,VS0,VS1	// VIU1 add data (no carries)
	cmpi	cr7,0,DBK,0xF	// IU1 Is last byte right justified?

	vaddcuw	VCAR2,VTEMP,VSUM //VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VTEMP,VSUM //VIU1	data + previous sum

	vadduwm	VCAR3,VCAR1,VCAR2 //VIU1 add carries from previous adds

	vadduwm	VCARF,VCAR3,VCARF //VIU1 update VCARF

	beq	cr7, Rt_just	// b if right justified.
	vsel	VS2,VS2,V0,VMM   // VIU1 Select src bytes left | zeroes right

Rt_just:
	vaddcuw	VCAR1,VS2,VSUM	// VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VS2,VSUM	// VIU1 data + previous sum (no carries)

	vadduwm	VCARF,VCAR1,VCARF	// VIU1 Update VCARF
	vmrglh	VL,V0,VSUM	// VPU separate low shorts of sum

	vmrghh	VH,V0,VSUM	//VPU separate high shorts of sum
	rlwinm	DBK,SP,0,0,27	// IU1 Align stack pointer to QW

	vsumsws	VCARS,VCARF,V0	 //VIU2 sum all carries 
	vadduwm	VSUM,VL,VH	//VIU1 add low and high data
	li	BK,-16		// IU1 Index 0x10 less than SP

	vsumsws	VFIN,VSUM,VCARS	//VIU2	sum all data including carries
        	
	stvx	VFIN,DBK,BK	// LSU Store partial checksum from VR
	
	lwz	SRC,-4(DBK)	// LSU Load partial checksum to GPR

	addc	SRC,SRC,SUM

	addze	SRC,SRC

	blr			// Return destination address from entry

#ifdef __MWERKS__
	.align	16
#else
	.align	4
#endif
GT_4QW_cs:	// Do once if nxt ld is from odd half of cache line, else twice

	lvx	VS1,SRC,BK	// LSU Get S3 (or S2)
	addi	QW,QW,-1	// IU1 Keeping track of QWs stored
	vaddcuw	VCAR1,VS0,VSUM	// VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VS0,VSUM	// VIU1 data + previous sum (no carries)
	mtcrf	0x02,DNX	// IU2 cr6[3]=((DST+32)[27]==1)?1:0;
	addi	DNX,DNX,16	// IU1 Update cr6 for next loop

	addi	Rt,QW,-2	// IU1 Insure at least 2 QW left after big loop
	vor	VS0,VS1,VS1	// VIU1 Move upper vector to lower

	addi	BK,BK,16	// IU1 Increment byte count by 16
	vadduwm	VCARF,VCAR1,VCARF	// VIU1 Update VCARF
	bdnzf	27,GT_4QW_cs	// b if next store is to lower (even) half of CL
// At this point next store will be to even address.

	mtcrf	0x02,DBK	// IU2 cr6[3]=((last load)[27]==1)?1:0; (odd?)
	addi	SP8,SRC,96	// IU1 Starting address for dcbt
	vxor	VS1,VS1,VS1	// VIU1 Zero before adding below

// We need the ctr register to reflect an even byte count before entering
// the next block - faster to decrement than to reload.

	bns	cr6,B32_cs	// b if DST[27] == 0; i.e, final load is even

	bdnz	B32_cs		// decrement counter for last QW load odd

B32_cs:	// Should be at least 2 loads remaining and next 2 are cache aligned
	lvx	VS2,SRC,BK	// LSU Get S4
	addi	BK,BK,16	// IU1 Increment byte count by 16
	vaddcuw	VCAR1,VS0,VS1	// VIU1 add data and store carries

	lvx	VS3,SRC,BK	// LSU Get S5
	addi	SP8,SP8,32	// IU1 Next starting address for dcbt
	vadduwm	VTEMP,VS0,VS1	// VIU1 add data (no carries)

	dcbt	0,SP8		// LSU Prefetch cache line 64 bytes ahead
	addi	BK,BK,16	// IU1 Increment byte count
	vaddcuw	VCAR2,VTEMP,VSUM //VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VTEMP,VSUM //VIU1	data + previous sum

	vadduwm	VCAR3,VCAR1,VCAR2 //VIU1 add carries from previous adds
	bdz	Nxt_loc_cs	// always decrement and branch to next instr		

Nxt_loc_cs:
	vadduwm	VCARF,VCAR3,VCARF //VIU1 update VCARF

	vor	VS0,VS2,VS2	// VIU1 Move S13 to S11

	vor	VS1,VS3,VS3	// VIU1 Move upper vector to lower
	bdnz	B32_cs		// b if there are at least two more QWs to do

	bso	cr6,One_even_QW_cs	// b if there is one even and one odd QW to store

	b	Last_ld_cs	// b if last store is to even address

// Come here with two more loads and two stores to do
One_even_QW_cs:
	lvx	VS2,SRC,BK	// LSU Get S6 (or S5 if if D-S>=0)
	addi	BK,BK,16	// IU1 Increment byte count
	vaddcuw	VCAR1,VS0,VS1	// VIU1 add data and store carries

	vadduwm	VTEMP,VS0,VS1	// VIU1 add data (no carries)

	vaddcuw	VCAR2,VTEMP,VSUM //VIU1 data + previous sum ->store carries

	vadduwm	VSUM,VTEMP,VSUM //VIU1	data + previous sum

	vadduwm	VCAR3,VCAR1,VCAR2 //VIU1 add carries from previous adds

	vadduwm	VCARF,VCAR3,VCARF //VIU1 update VCARF

	vxor	VS1,VS1,VS1	// VIU1 Zero before next add

	vor	VS0,VS2,VS2	// VIU1 Move S13 to S11
	b	Last_ld_cs

// End of vec_csum_partial in AltiVec

#endif /* __ppc__ */
