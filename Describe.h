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

#ifndef _DESCRIBE_H_
#define _DESCRIBE_H_

@class NSString;
@class NSData;
@protocol NSObject;

/* represents the level of the object in the protocol stack */
enum _stacklev {SL_NONE,
				SL_PHYSICAL,
				SL_DATALINK,
				SL_NETWORK,
				SL_TRANSPORT,
				SL_SESSION,
				SL_PRESENTATION,
				SL_APPLICATION};

typedef enum _stacklev stacklev;

@protocol Describe <NSObject>

/*
	Returns an NSString of the short name of the protocol which the object
	decodes, such as "IPv4". Returns nil if the object does not have a name.
	(Such as if it just contains other Decode objects, and does not perform
	any decoding itself).
*/
+ (NSString *)shortName;

/*
	Returns an NSString of the long name of the protocol which the object decodes,
	such as "Internet Protocol version 4". Returns nil if the object does not
	have a name.
*/
+ (NSString *)longName;

/*
	Returns an NSString providing a short informational string about the object,
	such as for an object that decodes TCP headers, it may state the flags which
	are set in the header (i.e, SYN, ACK etc). Returns nil if the object does not
	provide an information string.
*/
- (NSString *)info;

/*
	Returns a value corresponding to the position of the object in the
	protocol stack, as per the OSI reference model.
*/
- (stacklev)level;

@end

#endif
