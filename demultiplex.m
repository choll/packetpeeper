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

#include <stddef.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#include "Decode.h"
#include "PPDecoderParent.h"
#include "demultiplex.h"

/*
	Demultiplexes the NSData object at the first argument into
	<Decode> objects which are placed into the NSArray at the
	second argument, using the <Decode> object at the third
	argument as a parent from which to obtain the linklayer.
	Returns the number of bytes of the NSData object processed.
*/

int demultiplex_data(NSData *data, NSMutableArray *outlist, id <PPDecoderParent> parent, Class layer)
{
	id <Decode> obj;
	void *ptr;
	unsigned int nbytes;	/* number of bytes processed from 'data' object, this is returned */
	unsigned int ptrlen;

	if(data == nil || outlist == nil)
		return -1;

	ptr = (void *)[data bytes];
	ptrlen = [data length];
	[data retain];
	nbytes = 0;

	while(ptrlen > 0 && layer != Nil) {
		obj = [[layer alloc] initWithData:data parent:parent];
		[data release];

		if(obj == nil) 
			return nbytes;

		[outlist addObject:obj];
		layer = [obj nextLayer];

		ptr += [obj frontSize];
		nbytes += ([obj frontSize] + [obj rearSize]);

		/* this should never occur, so must be properly indicated by ret -1 */
		if(([obj frontSize] + [obj rearSize]) > ptrlen)
			return -1;

		ptrlen -= ([obj frontSize] + [obj rearSize]);
		[obj release];

		if((data = [[NSData alloc] initWithBytesNoCopy:ptr length:ptrlen freeWhenDone:NO]) == nil)
			return -1;
	}
	[data release];
	return nbytes;
}
