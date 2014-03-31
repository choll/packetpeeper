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

#ifndef _LOOPBACKDECODE_H_
#define _LOOPBACKDECODE_H_

#include <stdint.h>
#import <Foundation/NSObject.h>
#include "Decode.h"
#include "Describe.h"
#include "ColumnIdentifier.h"
#include "OutlineViewItem.h"

/* this might change - so use a typedef just in case it does,
   also note that on some systems (OpenBSD) it can be in
   network byte order */
typedef uint32_t loopback_type;

@class NSData;

@interface LoopbackDecode : NSObject <Decode, Describe, NSCoding, OutlineViewItem, ColumnIdentifier>
{
	loopback_type type;
}

@end

#endif /* _LOOPBACKDECODE_H_ */
