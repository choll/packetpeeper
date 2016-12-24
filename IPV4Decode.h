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
- (size_t)length;
- (size_t)headerLength;
- (unsigned int)fragmentOffset;
- (struct in_addr)in_addrSrc;
- (struct in_addr)in_addrDst;
- (NSData *)optionsData;

/* private method */
- (id <OutlineViewItem>)resolvCallback:(void *)data;

@end

#endif /* _IPV4DECODE_H_ */
