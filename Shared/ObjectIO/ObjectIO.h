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

#ifndef _OBJECTIO_H_
#define _OBJECTIO_H_

#include "../ErrorStack.h"
#import <Foundation/NSObject.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

// XXX config.h
#define READOBJ_BUFSIZ \
    (32 * 1024) /* initial buffer size used by readobj, 32k */
#define LEN_MAX (1024 * 1024 * 16) /* maximum allowable object length, 16MB */

#if (LEN_MAX > SIZE_MAX)
#error "LEN_MAX is greater than the maximum value of len_t"
#endif

/* Error stack codes */
#define EOBJIO_BADMD  1 /* Failed to create NSMutableData */
#define EOBJIO_BADLEN 2 /* Object too large */

@class NSMutableData;
@class NSSocketPort;

@interface ObjectIO : NSObject <ErrorStack>
{
    int fd;
    NSMutableData* writeData; /* belongs to write method */
    void* buf;                /* belongs to read method */
    size_t buflen;            /* belongs to read method */
    struct iovec riov[2];     /* belongs to read method */
    size_t rlen;              /* belongs to read method */
    ssize_t nread;            /* belongs to read method */
    BOOL more;
}

- (id)initWithFileDescriptor:(int)fdVal;
- (id)initWithSocketPort:(NSSocketPort*)socketPort;
- (ssize_t)write:(id<NSCoding>)obj;
- (id<NSCoding>)read;
- (BOOL)moreAvailable;

@end

#endif /* _OBJECTIO_H_ */
