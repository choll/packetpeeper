/*
 * Copyright 2007, Denis Vlasenko, vda.linux@googlemail.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef __i386__

#define PREFETCH(a) prefetchnta a
//#define PREFETCH(a) prefetch a
//#define PREFETCH(a)

//vda: 5 is best on Duron 650
#define ITER_BITS 5		/* ...5,6,7 - ...32,64,128 bytes */
				// tweak unrolled loop too...
#define ITER_SZ (1<<ITER_BITS)
#define ITER_MSK ((1<<ITER_BITS)-4)

/*
 * computes a partial checksum, e.g. for TCP/UDP fragments
 */

/*
unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum)
*/

.text
.align 4
.globl _sse_csum_partial

/* csumming is done in 4 stages:
1. Make src dword aligned
2. Jump in the middle of unrolled loop (so 1st pass will be partial)
3. Perform the loop
4. Handle last 1,2,3 bytes if needed
*/

_sse_csum_partial:
	pushl	%esi
	pushl	%ebx
	movl	20(%esp),%eax	// Function arg: unsigned int sum
	movl	16(%esp),%ecx	// Function arg: int len
	movl	12(%esp),%esi	// Function arg:	const unsigned char *buf

	testl	$2, %esi
	jnz	label_30
label_10:				// esi is dword aligned now
	PREFETCH((%esi))
	PREFETCH(64(%esi))
	PREFETCH(128(%esi))
	PREFETCH(192(%esi))
	movl	%ecx, %edx
	movl	%ecx, %ebx
	andl	$ITER_MSK, %ebx	// = bytes to handle in first (partial) iteration
	shrl	$ITER_BITS, %ecx // = iterations to make 
	addl	%ebx, %esi	// => 1st byte to handle in 2nd complete iteration
	shrl	$2, %ebx	// = dwords to handle
	negl	%ebx
	lea	label_45(%ebx,%ebx,2), %ebx // = label_45 - 3*dwords_to_handle
	testl	%esi, %esi	// clear CF
	jmp	*%ebx		// here we go!

	// Handle 2-byte-aligned regions
label_20:	addw	(%esi), %ax	// more than 2 bytes: eat two
	lea	2(%esi), %esi
	adcl	$0, %eax
	jmp	label_10

label_30:	subl	$2, %ecx
	ja	label_20
	je	label_32
	movzbl	(%esi),%ebx	// csumming 1 byte, 2-aligned
	addl	%ebx, %eax
	jmp	label_80
label_32:
	addw	(%esi), %ax	// csumming 2 bytes, 2-aligned
	jmp	label_80
label_40:
	PREFETCH(256(%esi))
label_41:
/*
	addl	-128(%esi), %eax
	adcl	-124(%esi), %eax
	adcl	-120(%esi), %eax
	adcl	-116(%esi), %eax
	adcl	-112(%esi), %eax
	adcl	-108(%esi), %eax
	adcl	-104(%esi), %eax
	adcl	-100(%esi), %eax
	adcl	-96(%esi), %eax
	adcl	-92(%esi), %eax
	adcl	-88(%esi), %eax
	adcl	-84(%esi), %eax
	adcl	-80(%esi), %eax
	adcl	-76(%esi), %eax
	adcl	-72(%esi), %eax
	adcl	-68(%esi), %eax
	adcl	-64(%esi), %eax
	adcl	-60(%esi), %eax
	adcl	-56(%esi), %eax
	adcl	-52(%esi), %eax
	adcl	-48(%esi), %eax
	adcl	-44(%esi), %eax
	adcl	-40(%esi), %eax
	adcl	-36(%esi), %eax*/
	addl	-32(%esi), %eax
	adcl	-28(%esi), %eax
	adcl	-24(%esi), %eax
	adcl	-20(%esi), %eax
	adcl	-16(%esi), %eax
	adcl	-12(%esi), %eax
	adcl	-8(%esi), %eax
	adcl	-4(%esi), %eax
label_45:
	adcl	$0, %eax
	lea	ITER_SZ(%esi), %esi	// does NOT change CF!
	dec	%ecx			// does NOT change CF!
    // We can do just "jge 40b" here, but we can be a bit clever...
    // This little twist gives surprisingly noticeable benefits!
    // Seen 11% increase on random 1K blocks on Duron 650
	js	label_46			
	cmp	$8,%ecx			
	jae	label_40	// need prefetch
	jmp	label_41	// do not need it
label_46:
	//adcl	$0, %eax
	movl	%edx, %ecx
	andl	$3, %ecx
	jz	label_90

	// Handle the last 1-3 bytes without jumping
	notl	%ecx		// 1->2, 2->1, 3->0, higher bits are masked
				// by the shll and shrl instructions
	movl	$0x00ffffff, %ebx	
	shll	$3, %ecx
	shrl	%cl, %ebx
	andl	-ITER_SZ(%esi), %ebx	// esi is 4-aligned so should be ok
	addl	%ebx, %eax
label_80: 
	adcl	$0, %eax
label_90:
	popl	%ebx
	popl	%esi
	ret

#endif /* __i386__ */
