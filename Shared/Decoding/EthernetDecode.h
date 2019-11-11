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

#ifndef _ETHERNETDECODE_H_
#define _ETHERNETDECODE_H_

#include "../../PacketPeeper/UI Classes/ColumnIdentifier.h"
#include "Decode.h"
#include "../../PacketPeeper/Describe.h"
#include "../../PacketPeeper/UI Classes/OutlineViewItem.h"
#import <Foundation/NSObject.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <sys/types.h>

/* minimum amount of data required to decode the header (not related to minimum
   ethernet packet length) */
#define ETHERNETDECODE_HDR_MIN ETHER_HDR_LEN

@class NSData;

@interface EthernetDecode
    : NSObject <Decode, Describe, NSCoding, OutlineViewItem, ColumnIdentifier>
{
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type; /* ETHER_TYPE_LEN = 2 */
}

@end

#endif /* _ETHERNETDECODE_H_ */
