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

#ifndef _MESSAGES_H_
#define _MESSAGES_H_

#include <sys/time.h>
#include <objc/objc.h>
#import <Foundation/NSObject.h>

@class NSString;
@class PPBPFProgram;
@protocol NSCoding;

@interface MsgQuit : NSObject <NSCoding> {}
@end

@interface MsgSettings : NSObject <NSCoding>
{
	NSString		*iface;			/* string of which interface we are to use, eg 'en0' */
	unsigned int	buflen;			/* buffer length for reads on bpf device */
	struct timeval	timeout;		/* timeout for reads on the bpf device */
	BOOL			promisc;		/* enable/disable promiscuous mode on the interface */
	BOOL			immediate;		/* enable/disable immediate mode on the bpf device */
	PPBPFProgram	*filterProgram;
}

- (id)initWithInterface:(NSString *)ifaceVal bufLength:(unsigned int)buflenVal timeout:(struct timeval *)timeoutVal promiscuous:(BOOL)promiscVal immediate:(BOOL)immediateVal filterProgram:(PPBPFProgram *)aFilterProgram;
- (NSString *)interface;
- (unsigned int)bufLength;
- (struct timeval *)timeout;
- (BOOL)promiscuous;
- (BOOL)immediate;
- (PPBPFProgram *)filterProgram;

@end

#endif /* _MESSAGES_H_ */
