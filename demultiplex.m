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

#include "demultiplex.h"
#include "Decode.h"
#include "PPDecoderParent.h"
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#include <stddef.h>

/*
    Demultiplexes the NSData object at the first argument into
    <Decode> objects which are placed into the NSArray at the
    second argument, using the <Decode> object at the third
    argument as a parent from which to obtain the linklayer.
    Returns the number of bytes of the NSData object processed.
*/

size_t demultiplex_data(
    NSData* data,
    NSMutableArray* outlist,
    id<PPDecoderParent> parent,
    Class layer)
{
    id<Decode> obj;
    const char* ptr;
    size_t
        nbytes; /* number of bytes processed from 'data' object, this is returned */
    size_t ptrlen;

    if (data == nil || outlist == nil)
        return -1;

    ptr = [data bytes];
    ptrlen = [data length];
    [data retain];
    nbytes = 0;

    while (ptrlen > 0 && layer != Nil)
    {
        obj = [[layer alloc] initWithData:data parent:parent];
        [data release];

        if (obj == nil)
            return nbytes;

        [outlist addObject:obj];
        [obj release]; // rely on NSMutableArray.addObject's retain

        /* this should never occur */
        if (([obj frontSize] + [obj rearSize]) > ptrlen)
            return -1;

        ptr += [obj frontSize];
        ptrlen -= ([obj frontSize] + [obj rearSize]);
        nbytes += ([obj frontSize] + [obj rearSize]);

        if ((data = [[NSData alloc] initWithBytesNoCopy:(void*)ptr
                                                 length:ptrlen
                                           freeWhenDone:NO]) == nil)
            return -1;

        layer = [obj nextLayer];
    }
    [data release];
    return nbytes;
}
