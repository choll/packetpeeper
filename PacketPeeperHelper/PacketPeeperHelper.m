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
#include "../Shared/ErrorStack.h"
#include "../Shared/ObjectIO/Messages.h"
#include "../Shared/ObjectIO/ObjectIO.h"
#include "../Shared/Decoding/Packet.h"
#include "../Shared/PacketPeeper.h"
#include "../Shared/Decoding/dlt_lookup.h"
#include "../Shared/ObjectIO/socketpath.h"
#import <Foundation/NSArray.h>
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSData.h>
#import <Foundation/NSDate.h>
#import <Foundation/NSString.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/bpf.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

// XXX these should be in some kind of 'config.h' file, merge with socketpath.h
#define CHROOT_DIR "/var/empty" /* directory to chroot to */
#define USER       "nobody" /* username to change to */ // need to adduser "capture"

// XXX need to go into their own .c/.h files really.. chrootuser at least
// err_exit just in a .h
void err_exit(ObjectIO* objio);
int chrootuser(const char* dirname, const char* login);
int init_objio(id* obj, const char* path);

int main(void)
{
    int sock_fd;             /* socket fd */
    int bpf_fd;              /* bpf fd */
    int n;                   /* select return value */
    unsigned int poolcount;  /* counter for autorelease pool */
    struct timeval* timeout; /* select timeout value */
    struct fd_set rset;      /* select read fd's */
    Bpf* bpf;                /* bpf object (see bpf(4)) */
    id obj;                  /* stores object read from fd_out */
    ObjectIO* objio;
    NSAutoreleasePool* pool;

    (void)close(STDIN_FILENO);
    (void)close(STDOUT_FILENO);
    (void)close(STDERR_FILENO);

    if ((sock_fd = init_objio(&objio, SOCKETPATH)) == -1)
    {
        exit(EXIT_FAILURE);
    }

    pool = [[NSAutoreleasePool alloc] init];

    /* malloc used because the timeout data is only used once */
    if ((timeout = malloc(sizeof(*timeout))) == NULL)
    {
        [[ErrorStack sharedErrorStack]
            pushError:@"Failed to allocate memory for select(2) timeout data"
               lookup:[PosixError class]
                 code:errno
             severity:ERRS_ERROR];
        err_exit(objio);
    }

    if ((bpf = [[Bpf alloc] init]) == nil)
        err_exit(objio);

    bpf_fd =
        [bpf fd]; /* the bpf file descriptor is needed for use with select */

    if (chrootuser(CHROOT_DIR, USER) == -1)
    {
        [[ErrorStack sharedErrorStack] pushError:@"Failed to drop privileges"
                                          lookup:[PosixError class]
                                            code:errno
                                        severity:ERRS_ERROR];
        err_exit(objio);
    }

    /* set timer for the settings data */

    timeout->tv_sec = 60; //  XXX config.h
    timeout->tv_usec = 0;

    FD_ZERO(&rset);
    FD_SET(sock_fd, &rset);

    poolcount = 0;

    while ((n = select(bpf_fd + 1, &rset, NULL, NULL, timeout)) > 0)
    {
        if (FD_ISSET(sock_fd, &rset))
        {
            do
            {
                if ((obj = [objio read]) == nil)
                    err_exit(objio);
                [obj retain];
                if ([obj isMemberOfClass:[MsgSettings class]])
                {
                    [bpf setInterface:[obj interface]];
                    [bpf setBufLength:[obj bufLength]];
                    [bpf setTimeout:[obj timeout]];
                    [bpf setPromiscuous:[obj promiscuous]];
                    [bpf setImmediate:[obj immediate]];
                    if ([obj filterProgram] != nil)
                        [bpf setFilterProgram:[obj filterProgram]];
                }
                else if ([obj isMemberOfClass:[MsgQuit class]])
                {
                    exit(EXIT_SUCCESS);
                }
                else
                {
                    [[ErrorStack sharedErrorStack]
                        pushError:@"Unknown object recieved by helper"
                           lookup:Nil
                             code:0
                         severity:ERRS_ERROR];
                    err_exit(objio);
                }
                [obj release];
            } while ([objio moreAvailable]);
        }

        if (FD_ISSET(bpf_fd, &rset))
        {
            Packet* pkt;
            NSArray* parray;
            unsigned int i;

            if ((parray = [bpf read]) == nil)
            {
                if ([[ErrorStack sharedErrorStack] code] != EBPF_TIMEOUT)
                    err_exit(objio);
            }
            else
            {
                [parray retain];
                for (i = 0; i < [parray count]; ++i)
                {
                    struct bpf_hdr* hdr;
                    NSData* data;
                    NSData* tempData;

                    data = [parray objectAtIndex:i];

                    if ([data length] < sizeof(struct bpf_hdr))
                        continue;

                    hdr = (struct bpf_hdr*)[data bytes];

                    /* this may seem spurious, but the bpf header may also include padding for
					   data alignment, so we still need to check we got more than just this. */
                    if (hdr->bh_hdrlen > [data length])
                        continue;

                    /* remove the bpf header from data */
                    if ((tempData = [[NSData alloc]
                             initWithBytesNoCopy:(uint8_t*)[data bytes] +
                                                 hdr->bh_hdrlen
                                          length:[data length] - hdr->bh_hdrlen
                                    freeWhenDone:NO]) == nil)
                        err_exit(objio);

                    if ((pkt = [[Packet alloc]
                              initWithData:tempData
                             captureLength:hdr->bh_caplen
                              actualLength:hdr->bh_datalen
                                 timestamp:TIMEVAL_TO_NSDATE(hdr->bh_tstamp)
                                 linkLayer:dlt_lookup([bpf linkType])]) == nil)
                    {
                        err_exit(objio);
                    }

                    [tempData release];

                    if ([objio write:pkt] <= 0)
                        err_exit(objio);

                    [pkt release];
                }
                [parray release];
            }
        }

        if (++poolcount > 100)
        { // XXX config.h
            [pool release];
            pool = [[NSAutoreleasePool alloc] init];
            poolcount = 0;
        }

        /* a timeout is only used on the first iteration of the loop,
		   when we recieve capture settings. Also provides a convenient
		   place to start the capture. */
        if (timeout != NULL)
        {
            free(timeout);
            timeout = NULL;
            if ([bpf start] == NO)
                err_exit(objio);
        }
        FD_ZERO(&rset);
        FD_SET(sock_fd, &rset);
        FD_SET(bpf_fd, &rset);
    }

    (void)close(sock_fd);
    [bpf release];
    [objio release];
    [pool release];
    exit(EXIT_SUCCESS);
}

void err_exit(ObjectIO* objio)
{
    [objio write:[ErrorStack sharedErrorStack]];
    exit(EXIT_FAILURE);
}

int chrootuser(const char* dirname, const char* login)
{
    struct passwd* pw;

    if ((pw = getpwnam(login)) == NULL)
        return -1;

    if (initgroups(pw->pw_name, pw->pw_gid) == -1)
        return -1;

    endgrent();

    if (chdir(dirname) == -1)
        return -1;

    if (chroot(dirname) == -1)
        return -1;

    if (setgid(pw->pw_gid) == -1)
        return -1;

    if (setuid(pw->pw_uid) == -1)
        return -1;

    endpwent();

    return 0;
}

/* set up an ObjectIO object with a local socket at 'path' */
int init_objio(id* obj, const char* path)
{
    struct sockaddr_un s_addr;
    int ret;

    if ((ret = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
        return -1;

    s_addr.sun_family = AF_LOCAL;

    if (strlcpy(s_addr.sun_path, path, sizeof(s_addr.sun_path)) >=
        sizeof(s_addr.sun_path))
        return -1;

    if (connect(ret, (struct sockaddr*)&s_addr, sizeof(s_addr)) == -1)
        return -1;

    if ((*obj = [[ObjectIO alloc] initWithFileDescriptor:ret]) == nil)
        return -1;

    return ret;
}
