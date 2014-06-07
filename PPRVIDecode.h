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

#ifndef PACKETPEEPER_RVIDECODE_H
#define PACKETPEEPER_RVIDECODE_H

#include "Decode.h"
#include "Describe.h"
#include "OutlineViewItem.h"
#include "ColumnIdentifier.h"

#import <Foundation/NSObject.h>

#include <stdint.h>

struct pp_pktap_header;

@interface PPRVIDecode : NSObject <Decode, Describe, NSCoding, OutlineViewItem, ColumnIdentifier>
{
    struct pp_pktap_header* m_hdr;
    id <PPDecoderParent> m_parent;
}

- (uint32_t)dlt;

@end

#endif

