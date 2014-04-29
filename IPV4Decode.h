/*
 * Packet Peeper
 * Copyright 2006, 2007, 2008, 2014 Chris E. Holloway
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

#ifndef _IPV4DECODE_H_
#define _IPV4DECODE_H_

#include <stdint.h>
#include <netinet/in.h>
#import <Foundation/NSObject.h>
#include "Decode.h"
#include "Describe.h"
#include "OutlineViewItem.h"
#include "ColumnIdentifier.h"

#define IPV4DECODE_HDR_MIN		(sizeof(struct ip))

#ifndef IPOPT_SECUR_PROG
	#define IPOPT_SECUR_PROG	0x5E26
#endif

#define OPTION_END						0x0 /* only used in serialization */
#define OPTION_NOP						0x1
#define OPTION_SECURITY					0x2
#define OPTION_STREAM_ID				0x3
#define OPTION_LOOSE_SRC_REC_ROUTE		0x4
#define OPTION_STRICT_SRC_REC_ROUTE		0x5
#define OPTION_REC_ROUTE				0x6
#define OPTION_TIMESTAMP				0x7

#define OPTION_SECURITY_UNKNOWN			0xFF
#define OPTION_SECURITY_UNCLASSIFIED	0x0
#define OPTION_SECURITY_CONFIDENTIAL	0x1
#define OPTION_SECURITY_EFTO			0x2
#define OPTION_SECURITY_MMMM			0x3
#define OPTION_SECURITY_PROG			0x4
#define OPTION_SECURITY_RESTRICTED		0x5
#define OPTION_SECURITY_SECRET			0x6
#define OPTION_SECURITY_TOPSECRET		0x7

@class NSData;
@class NSString;
@class HostCache;
@protocol PPDecoderPlugin;

@interface IPV4Decode : NSObject <Decode, Describe, NSCoding, OutlineViewItem, ColumnIdentifier>
{
	id <PPDecoderParent> parent;
	struct in_addr src;
	struct in_addr dst;
	uint16_t tlen;		/* total length */
	uint16_t ident;
	uint16_t sum;
	uint16_t offset;
	uint16_t calced_sum;
	uint8_t version;	/* version, 4 bits */
	uint8_t hlen;		/* header length, 4 bits, measured in 32bit words */
	uint8_t tos;		/* type of service */
	uint8_t flags;
#define IPV4DECODE_FLAGS_RES	0x80	/* reserved */
#define IPV4DECODE_FLAGS_DFRAG	0x40	/* dont fragment */
#define IPV4DECODE_FLAGS_MFRAG	0x20	/* more fragments */
	uint8_t ttl;
	uint8_t proto;
	id <PPDecoderPlugin> optionsDecoder;
}

- (NSString *)addrTo;
- (NSString *)addrFrom;
- (NSString *)resolvTo;
- (NSString *)resolvFrom;
- (NSString *)to;
- (NSString *)from;
- (uint8_t)protocol;
- (BOOL)isChecksumValid;
- (uint16_t)computedChecksum;
- (NSString *)flagsMeaning;
- (BOOL)dontFragmentFlag;
- (BOOL)moreFragmentsFlag;
- (unsigned int)length;
- (unsigned int)headerLength;
- (unsigned int)fragmentOffset;
- (struct in_addr)in_addrSrc;
- (struct in_addr)in_addrDst;
- (NSData *)optionsData;

/* private method */
- (id <OutlineViewItem>)resolvCallback:(void *)data;

@end

#endif /* _IPV4DECODE_H_ */
