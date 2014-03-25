/*
 * Packet Peeper
 * Copyright 2006, 2007, Chris E. Holloway
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

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#import <Foundation/NSArchiver.h>
#import <Foundation/NSPort.h>
#import <Foundation/NSData.h>
#import <Foundation/NSString.h>
#include "writevn.h"
#include "ErrorStack.h"
#include "ObjectIO.h"

@implementation ObjectIO

+ (NSString *)stringForErrorCode:(unsigned int)code
{
	switch(code) {
		case EOBJIO_BADMD:
			return @"NSMutableData returned nil";

		case EOBJIO_BADLEN:
			return @"Object length too large";

		default:
			return nil;
	}
}

+ (NSString *)errorDomain
{
	return @"ObjectIO";
}

- (id)initWithFileDescriptor:(int)fdVal
{
	if((self = [super init]) != nil) {
		if((writeData = [[NSMutableData alloc] init]) == nil) {
			[[ErrorStack sharedErrorStack] pushError:@"Could not init" lookup:[self class] code:EOBJIO_BADMD severity:ERRS_ERROR];
			return nil;
		}
		if((buf = malloc(READOBJ_BUFSIZ)) == NULL) {
			[[ErrorStack sharedErrorStack] pushError:@"Failed to allocate memory" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
			return nil;
		}
		fd = fdVal;
		buflen = READOBJ_BUFSIZ;
		nread = 0;
		more = NO;
	}
	return self;
}

- (id)initWithSocketPort:(NSSocketPort *)socketPort
{
	return [self initWithFileDescriptor:[socketPort socket]];
}

- (id)init
{
	/* initWithFileDescriptor is the designated initializer */
	[super dealloc];
	return nil;
}

- (id <NSCoding>)read
{
	size_t nleft;
	NSData *data;
	id obj;

	riov[0].iov_base = &rlen;
	riov[0].iov_len = sizeof(rlen);
	riov[1].iov_base = buf;
	riov[1].iov_len = buflen;

	while(nread < riov[0].iov_len) { /* if we dont yet have the length field */
		riov[0].iov_base = (uint8_t *)riov[0].iov_base + nread;
		riov[0].iov_len -= nread;
		if((nread = readv(fd, riov, 2)) <= 0) {
			if(nread == 0) // XXX handle zero properly in the error handler
				errno = 0;
			[[ErrorStack sharedErrorStack] pushError:@"Failed to readv ObjectIO data" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
			return nil;
		}
	}

	nread -= riov[0].iov_len; /* update nread so it does not include anything of 'len' */

	if(rlen > LEN_MAX) {
		/* we could read in and discard the too large object, but writeobj should never write
		   something so large, so we simply return nil here and do not expect to be called again,
			as communications with the sender should be terminated. */
		[[ErrorStack sharedErrorStack] pushError:@"Could not handle input ObjectIO data" lookup:[self class] code:EOBJIO_BADLEN severity:ERRS_ERROR];
		return nil;
	}

	/* now we have the length of the object properly stored in the len variable */
	if(nread == rlen) {
		nleft = 0;
	} else if(nread < rlen) { /* if we did not yet read the full object, read the rest in */
		if(rlen > buflen) { /* allocate more memory if needed */
			void *temp;
			if((temp = realloc(buf, rlen)) == NULL) {
				free(buf);
				[[ErrorStack sharedErrorStack] pushError:@"Failed to realloc extra memory" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
				return nil;
			}
			buf = temp;
			buflen = rlen;
		}

		nleft = rlen - nread;
		riov[1].iov_base = (uint8_t *)buf + nread;
		riov[1].iov_len = nleft;

		/* read in the rest of the object */
		while(nleft > 0) {
			if((nread = read(fd, riov[1].iov_base, riov[1].iov_len)) == -1) {
				[[ErrorStack sharedErrorStack] pushError:@"Failed to read ObjectIO data" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
				return nil;
			}

			nleft -= nread;
			riov[1].iov_base = (uint8_t *)riov[1].iov_base + nread;
			riov[1].iov_len += nread;
		}
	} else /* nread > len, we have extra data */
		nleft = 1;

	/* now we have the complete object read in */

	data = [[NSData alloc] initWithBytesNoCopy:buf length:rlen freeWhenDone:NO];
	obj = [NSUnarchiver unarchiveObjectWithData:data];
	[data release];

	if(nleft) { /* if we have extra data to deal with */
		nread -= rlen; /* this is how much of the next object(s) we have read */

		if(nread > sizeof(size_t)) {
			size_t prevlen = rlen;
			(void)memcpy(&rlen, buf + prevlen, sizeof(size_t));
			(void)memmove(buf, buf + prevlen + sizeof(size_t), nread - sizeof(size_t));
		} else
			(void)memcpy(&rlen, buf + rlen, nread);

		more = YES;
	} else {
		nread = 0;
		more = NO;
	}

	return obj;
}

- (ssize_t)write:(id <NSCoding>)obj
{
	NSArchiver *arc;
	struct iovec wiov[2];
	ssize_t ret;
	size_t wlen;

	// XXX need to check the return value of NSArchiver
	arc = [[NSArchiver alloc] initForWritingWithMutableData:writeData];
	[arc encodeRootObject:obj];
	wlen = [writeData length];
	[arc release];

	if(wlen > LEN_MAX) {
		[[ErrorStack sharedErrorStack] pushError:@"Could not handle output ObjectIO data" lookup:[self class] code:EOBJIO_BADLEN severity:ERRS_ERROR];
		return -1;
	}

	wiov[0].iov_base = &wlen;
	wiov[0].iov_len = sizeof(wlen);
	wiov[1].iov_base = (void *)[writeData bytes];
	wiov[1].iov_len = wlen;

	if((ret = writevn(fd, wiov, 2)) <= 0) {
		if(ret == 0)
			errno = 0;
		[[ErrorStack sharedErrorStack] pushError:@"Failed to writevn ObjectIO data" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
		return ret;
	}

	[writeData setLength:0];
	return ret;
}

- (BOOL)moreAvailable
{
	return more;
}

- (void)dealloc
{
	free(buf);
	[writeData release];
	[super dealloc];
}

@end
