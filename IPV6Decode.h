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

#ifndef PACKETPEEPER_IPV6DECODE_H
#define PACKETPEEPER_IPV6DECODE_H

#include <stdint.h>
#include <netinet/in.h>
#import <Foundation/NSObject.h>
#include "Decode.h"
#include "Describe.h"
#include "OutlineViewItem.h"
#include "ColumnIdentifier.h"

#define PACKETPEEPER_IP64DECODE_HDR_MIN		(sizeof(struct ip))

#ifndef IPOPT_SECUR_PROG
	#define IPOPT_SECUR_PROG	0x5E26
#endif

@class NSData;
@class NSString;
@class HostCache;
@protocol PPDecoderPlugin;

@interface IPV6Decode : NSObject <Decode, Describe, NSCoding, OutlineViewItem, ColumnIdentifier>
{
    struct ip6_hdr *m_hdr;
    id <PPDecoderParent> m_parent;
}

- (NSString *)addrTo;
- (NSString *)addrFrom;
- (NSString *)resolvTo;
- (NSString *)resolvFrom;
- (NSString *)to;
- (NSString *)from;
- (uint8_t)nextHeader;
- (unsigned int)length;
- (unsigned int)headerLength;
- (struct in6_addr)in6_addrSrc;
- (struct in6_addr)in6_addrDst;

/* private method */
- (id <OutlineViewItem>)resolvCallback:(void *)data;

@end

#endif

