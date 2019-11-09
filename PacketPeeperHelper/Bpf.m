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

#include "Bpf.h"
#include "ErrorStack.h"
#include "PPBPFProgram.h"
#import <Foundation/NSArray.h>
#import <Foundation/NSData.h>
#import <Foundation/NSException.h>
#import <Foundation/NSString.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

@implementation Bpf

+ (NSString*)stringForErrorCode:(unsigned int)code
{
    switch (code)
    {
    case EBPF_BADOP:
        return @"Invalid operation for object state";

    case EBPF_TIMEOUT:
        return @"Read timed out";

    default:
        return nil;
    }
}

+ (NSString*)errorDomain
{
    return @"Bpf";
}

- (id)initWithAttempts:(unsigned int)attempts
{
    if ((self = [super init]) != nil)
    {
        unsigned int i;
        char dev[sizeof "/dev/bpf" + 2]; /* MAX_OPEN_ATTEMPTS = 100 */

        fd = -1;

        NSAssert(
            attempts <= MAX_OPEN_ATTEMPTS && attempts > 0,
            @"Number of bpf open attempts is out of range");

        for (i = 0; i < attempts; ++i)
        {
            int ret;

            ret = snprintf(dev, sizeof(dev), "/dev/bpf%d", i);

            if (ret >= sizeof(dev) || ret < 0)
            {
                [[ErrorStack sharedErrorStack]
                    pushError:@"Not enough memory for snprintf"
                       lookup:[PosixError class]
                         code:errno
                     severity:ERRS_ERROR];
                goto err;
            }

            if ((fd = open(dev, O_RDONLY)) == -1)
            {
                if (errno != EBUSY) /* some other error occured */
                    break;
            }
            else
                break;
        }

        if (fd == -1)
        {
            [[ErrorStack sharedErrorStack]
                pushError:@"Could not open bpf device"
                   lookup:[PosixError class]
                     code:errno
                 severity:ERRS_ERROR];
            goto err;
        }

        buf = NULL;
        iface = DEFAULT_INTERFACE;
        parray = nil;
        promisc = NO;
        immediate = NO;
        buflen = 0;
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        linkType = EINVAL;
        filterProgram = nil;
    }
    state = STATE_INIT;
    return self;

err:
    [self dealloc];
    return nil;
}

- (id)init
{
    return [self initWithAttempts:OPEN_ATTEMPTS];
}

- (BOOL)start
{
    unsigned int temp;

    if (state != STATE_INIT)
    {
        [[ErrorStack sharedErrorStack] pushError:@"Could not start capture"
                                          lookup:[self class]
                                            code:EBPF_BADOP
                                        severity:ERRS_ERROR];
        return NO;
    }

    if (immediate)
    {
        temp = 1;
        if (ioctl(fd, BIOCIMMEDIATE, &temp) == -1)
        {
            [[ErrorStack sharedErrorStack]
                pushError:@"Could not enable immediate mode"
                   lookup:[PosixError class]
                     code:errno
                 severity:ERRS_ERROR];
            return NO;
        }
    }

    if (buflen)
    { /* if the user has set the buffer length, set it */
        if (ioctl(fd, BIOCSBLEN, &buflen) == -1)
        {
            [[ErrorStack sharedErrorStack]
                pushError:@"Could not set bpf buffer length"
                   lookup:[PosixError class]
                     code:errno
                 severity:ERRS_ERROR];
            return NO;
        }
    }
    else if (ioctl(fd, BIOCGBLEN, &buflen) == -1)
    { /* else find out what it is */
        [[ErrorStack sharedErrorStack]
            pushError:@"Could not read bpf buffer length"
               lookup:[PosixError class]
                 code:errno
             severity:ERRS_ERROR];
        return NO;
    }

    if (timeout.tv_sec || timeout.tv_usec)
    {
        if (ioctl(fd, BIOCSRTIMEOUT, &timeout) == -1)
        {
            [[ErrorStack sharedErrorStack]
                pushError:@"Failed to enable bpf timeout settings"
                   lookup:[PosixError class]
                     code:errno
                 severity:ERRS_ERROR];
            return NO;
        }
    }

    {
        struct ifreq dev;
        (void)strlcpy(dev.ifr_name, [iface UTF8String], IFNAMSIZ);
        if (ioctl(fd, BIOCSETIF, &dev) == -1)
        {
            [[ErrorStack sharedErrorStack]
                pushError:@"Could not set bpf interface"
                   lookup:[PosixError class]
                     code:errno
                 severity:ERRS_ERROR];
            return NO;
        }
    }

    if (filterProgram != nil &&
        ioctl(fd, BIOCSETF, [filterProgram program]) == -1)
    {
        [[ErrorStack sharedErrorStack] pushError:@"Could not set filter program"
                                          lookup:[PosixError class]
                                            code:errno
                                        severity:ERRS_ERROR];
        return NO;
    }

    [filterProgram release];
    filterProgram = nil;

    if (promisc && ioctl(fd, BIOCPROMISC) == -1)
    {
        [[ErrorStack sharedErrorStack]
            pushError:@"Could not enable promiscuous mode"
               lookup:[PosixError class]
                 code:errno
             severity:ERRS_ERROR];
        return NO;
    }

    if (ioctl(fd, BIOCGDLT, &linkType) == -1)
    {
        [[ErrorStack sharedErrorStack]
            pushError:@"Failed to read interface link type"
               lookup:[PosixError class]
                 code:errno
             severity:ERRS_ERROR];
        return NO;
    }

    if ((buf = malloc(buflen)) == NULL)
    {
        [[ErrorStack sharedErrorStack]
            pushError:@"Failed to allocate memory for bpf buffer"
               lookup:[PosixError class]
                 code:errno
             severity:ERRS_ERROR];
        return NO;
    }

    if ((parray = [[NSMutableArray alloc] init]) == nil)
    {
        [[ErrorStack sharedErrorStack]
            pushError:@"Failed to allocate NSMutableArray"
               lookup:Nil
                 code:0
             severity:ERRS_ERROR];
        free(buf);
        buf = NULL;
        return NO;
    }

    state = STATE_RUNNING;
    return YES;
}

- (BOOL)flush
{
    if (state != STATE_RUNNING)
    {
        [[ErrorStack sharedErrorStack] pushError:@"Could not flush bpf device"
                                          lookup:[self class]
                                            code:EBPF_BADOP
                                        severity:ERRS_ERROR];
        return NO;
    }

    if (ioctl(fd, BIOCFLUSH) == -1)
    {
        [[ErrorStack sharedErrorStack] pushError:@"Could not flush bpf device"
                                          lookup:[PosixError class]
                                            code:errno
                                        severity:ERRS_ERROR];
        return NO;
    }

    return YES;
}

- (void)setTimeout:(struct timeval*)timeoutVal
{
    if (state != STATE_RUNNING)
        timeout = *timeoutVal;
}

- (void)setInterface:(NSString*)ifaceVal
{
    if (state != STATE_RUNNING)
    {
        [ifaceVal retain];
        [iface release];
        iface = ifaceVal;
    }
}

- (void)setPromiscuous:(BOOL)promiscVal
{
    if (state != STATE_RUNNING)
        promisc = promiscVal;
}

- (void)setImmediate:(BOOL)immediateVal
{
    if (state != STATE_RUNNING)
        immediate = immediateVal;
}

- (void)setBufLength:(unsigned int)buflenVal
{
    if (state != STATE_RUNNING)
        buflen = buflenVal;
}

- (void)setFilterProgram:(PPBPFProgram*)filterProgramVal
{
    [filterProgramVal retain];
    [filterProgram release];
    filterProgram = filterProgramVal;
}

- (BOOL)running
{
    return (state == STATE_RUNNING);
}

- (int)linkType
{
    return linkType;
}

- (NSArray*)read
{
    NSData* data;        /* packet data */
    struct bpf_hdr* hdr; /* bpf header found at start of packet */
    unsigned char* pkt;  /* points to the current packet in buf */
    ssize_t readno;      /* store return value of read(2) */

    if (state != STATE_RUNNING)
    {
        [[ErrorStack sharedErrorStack]
            pushError:@"Could not read data from bpf device"
               lookup:[self class]
                 code:EBPF_BADOP
             severity:ERRS_ERROR];
        return nil;
    }

    /* bh_caplen packet length we got, bh_datalen actual packet length */
    if ((readno = read(fd, buf, buflen)) == -1)
    {
        [[ErrorStack sharedErrorStack]
            pushError:@"Could not read data from bpf device"
               lookup:[PosixError class]
                 code:errno
             severity:ERRS_ERROR];
        return nil;
    }

    if (readno == 0)
    { /* if we read nothing */
        [[ErrorStack sharedErrorStack]
            pushError:@"Could not read data from bpf device"
               lookup:[self class]
                 code:EBPF_TIMEOUT
             severity:ERRS_WARNING];
        return nil;
    }

    pkt = buf;

    [parray removeAllObjects];

    do
    {
        hdr = (struct bpf_hdr*)pkt;
        data = [[NSData alloc]
            initWithBytesNoCopy:pkt
                         length:(hdr->bh_hdrlen + hdr->bh_caplen)
                   freeWhenDone:NO];
        [parray addObject:data];
        [data release];
        pkt += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
    } while (pkt < (buf + readno));

    return parray;
}

- (int)fd
{
    return fd;
}

- (void)dealloc
{
    if (fd != -1)
        (void)close(fd);

    if (buf != NULL)
        free(buf);

    [parray release];
    [iface release];
    [filterProgram release];
    [super dealloc];
}

- (NSString*)description
{
    return [NSString
        stringWithFormat:
            @"Bpf: %@, promiscuous mode: %d, immediate mode: %d, state = %d",
            iface,
            promisc,
            immediate,
            state];
}

- (BOOL)stats:(struct bpf_stat*)stat
{
    if (state != STATE_RUNNING)
        return NO;

    if (ioctl(fd, BIOCGSTATS, stat) == -1)
    {
        [[ErrorStack sharedErrorStack]
            pushError:@"Could not read bpf statistics"
               lookup:[PosixError class]
                 code:errno
             severity:ERRS_ERROR];
        return NO;
    }
    return YES;
}

@end
