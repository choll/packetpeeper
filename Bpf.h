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

#ifndef _BPF_H_
#define _BPF_H_

#include <sys/time.h>
#import <Foundation/NSObject.h>
#include "ErrorStack.h"

/* when trying to open a bpf device, make up to and including N attempts, eg /dev/bpf[0..n-1]
   As default OS X includes 4 such devices, but the default number of open attempts is 20
   to be on the safe side */

#define		OPEN_ATTEMPTS		20			/* default number of attempts */
#define		MAX_OPEN_ATTEMPTS	100			/* maximum number of attempts allowed */
#define		DEFAULT_INTERFACE	@"en0"		/* default interface to listen on */

/* ErrorStack error codes */
#define EBPF_BADOP		1		/* Invalid operation for object state */
#define EBPF_TIMEOUT	2		/* Read on bpf device timed out */

@class NSMutableArray;
@class NSString;
@class NSData;
@class PPBPFProgram;

enum _bpfstate {STATE_INIT, STATE_RUNNING};		/* possible states of object:
													INIT		- Initialized
													RUNNING		- Initialized, and Capture has started, reading from the device */

typedef enum _bpfstate bpfstate;

@interface Bpf : NSObject <ErrorStack>
{
	NSString		*iface;			/* string of which interface we are to use, eg 'en0' */
	NSMutableArray	*parray;			/* array returned by the 'read' method */
	int				fd;				/* file descriptor for bpf device */
	bpfstate		state;			/* current state of the object */
	unsigned char	*buf;			/* buffer for reading from the bpf device */
	unsigned int	buflen;			/* buffer length for reads on bpf device */
	struct timeval	timeout;		/* timeout for reads on the bpf device */
	BOOL			promisc;		/* enable/disable promiscuous mode on the interface */
	BOOL			immediate;		/* enable/disable immediate mode on the bpf device */
	unsigned int	linkType;		/* stores the link layer type of the interface, eg ethernet, ppp */
	PPBPFProgram	*filterProgram;	/* BPF filter program wrapper */
}

- (int)fd;
- (int)linkType;
- (BOOL)running;
- (void)setInterface:(NSString *)ifaceVal;
- (void)setPromiscuous:(BOOL)promiscVal;
- (void)setImmediate:(BOOL)immediateVal;
- (void)setBufLength:(unsigned int)buflenVal;
- (void)setTimeout:(struct timeval *)timeoutVal;
- (void)setFilterProgram:(PPBPFProgram *)filterProgramVal;

- (BOOL)stats:(struct bpf_stat *)stat;
- (BOOL)flush;

- (NSArray *)read;

- (id)initWithAttempts:(unsigned int)attempts;

- (BOOL)start;

@end

#endif /* _BPF_H_ */
