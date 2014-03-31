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

#ifndef _DECODE_H_
#define _DECODE_H_

@class Packet;
@class NSData;
@protocol NSObject;
@protocol PPDecoderParent;

@protocol Decode <NSObject>

/*
	Initializes a new object using dataVal as the source of data and parentVal
	as the parent object. parentVal maybe nil.

*/
- (id)initWithData:(NSData *)dataVal parent:(id <PPDecoderParent>)parentVal;

/*
	Sets the parent of the decoder.
*/
- (void)setParent:(id <PPDecoderParent>)parentVal;

/*
	Returns the amount of data processed by the decoder, from the front of the
	given data.
*/
- (unsigned int)frontSize;

/*
	Returns the amount of data processed by the decoder, from the rear of the
	given data.
*/
- (unsigned int)rearSize;

/*
	Returns the class that can decode the layer immediately below the called
	object (in the protocol stack). Returns Nil if unknown. Note that this
	attribute is not serialized with the rest of the object, so may also
	return Nil when the value would otherwise be returned.
*/
- (Class)nextLayer;

@end

#endif /* _DECODE_H_ */
