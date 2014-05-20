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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <errno.h>
#include <ifaddrs.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSString.h>
#include "ErrorStack.h"
#include "Interface.h"

#define IFSTR_ETHER	"Ethernet Adaptor"
#define IFSTR_LOOP	"Loopback Network"
#define IFSTR_PPP	"Point-to-Point Link"

@implementation Interface

+ (NSArray *)liveInterfaces
{
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;
	char *buf;
	char *lim;
	char *next;
	NSMutableArray *ret;
	NSString *shortname;
	NSString *longname;
	size_t needed;
	int linkType;
	int mib[6] = {CTL_NET,		/* mib tree; networking */
				PF_ROUTE,		/* routing table */
				0,				/* ? */
				0,				/* address family, 0 is wildcard */
				NET_RT_IFLIST,	/* type of info, survey interface list */
				0};				/* flags to mask with for NET_RT_FLAGS */

	buf = NULL;
	shortname = nil;
	longname = nil;
	ret = nil;

	/* find out how much memory is needed. */
	if(sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		[[ErrorStack sharedErrorStack] pushError:@"Could not find out how much memory is required for interface list" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
		goto err;
	}

	if((buf = malloc(needed)) == NULL) {
		[[ErrorStack sharedErrorStack] pushError:@"Could not allocate memory for interface list" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
		goto err;
	}

	/* get the info */
	if(sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
		[[ErrorStack sharedErrorStack] pushError:@"Could not read interface list data" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
		goto err;
	}

	/* alloc after possible errors can occur */
	if((ret = [[NSMutableArray alloc] init]) == nil) {
		[[ErrorStack sharedErrorStack] pushError:@"NSMutableArray failed to alloc" lookup:Nil code:0 severity:ERRS_ERROR];
		goto err;
	}

	lim = buf + needed;

	for(next = buf; next < lim; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;

		if(ifm->ifm_type == RTM_IFINFO && ifm->ifm_flags & IFF_UP) {
			Interface *iface;
			char *iftype_str;

			sdl = (struct sockaddr_dl *)(ifm + 1);

			switch(sdl->sdl_type) {
				case IFT_ETHER:
					iftype_str = IFSTR_ETHER;
					linkType = DLT_EN10MB;
					break;

				case IFT_PPP:
					iftype_str = IFSTR_PPP;
					linkType = DLT_PPP;
					break;

				case IFT_LOOP:
					iftype_str = IFSTR_LOOP;
					linkType = DLT_NULL;
					break;

				/* interfaces other than loopback, ethernet or ppp are unsupported */
				default:
					continue;
					/* NOTREACHED */
			}

			if((shortname = [[NSString alloc] initWithBytes:sdl->sdl_data length:sdl->sdl_nlen encoding:NSUTF8StringEncoding]) == nil ||
			   (longname = [[NSString alloc] initWithUTF8String:iftype_str]) == nil) {
				[[ErrorStack sharedErrorStack] pushError:@"NSString failed to alloc/init" lookup:Nil code:0 severity:ERRS_ERROR];
				goto err;
			}

			if((iface = [[Interface alloc] initWithShortName:shortname
									   longName:longname
									   promisc:(ifm->ifm_flags & IFF_PROMISC) != 0
									   loopback:(ifm->ifm_flags & IFF_LOOPBACK) != 0
									   netmask:0
									   linkType:linkType]) == nil) {
				[[ErrorStack sharedErrorStack] pushError:@"Interface failed to alloc/init" lookup:Nil code:0 severity:ERRS_ERROR];
				goto err;
			}
			[shortname release];
			[longname release];
			shortname = nil;
			longname = nil;
			[ret addObject:iface];
			[iface release];
		}
	}

	/* note that ret may be empty if no interfaces found */

	free(buf);
	[ret autorelease];
	return ret;

	err:
		if(buf != NULL)
			free(buf);
		[ret release];
		[shortname release];
		[longname release];
		return nil;
}

- (id)initWithShortName:(NSString *)shortNameVal longName:(NSString *)longNameVal promisc:(BOOL)promiscVal loopback:(BOOL)loopbackVal netmask:(uint32_t)netmaskVal linkType:(int)linkTypeVal
{
	if((self = [super init]) != nil) {
		shortName = [shortNameVal retain];
		longName = [longNameVal retain];
		promisc = promiscVal;
		loopback = loopbackVal;
		netmask = netmaskVal;
		linkType = linkTypeVal;
	}
	return self;
}

- (id)init
{
	return [self initWithShortName:@"default" longName:@"default" promisc:NO loopback:NO netmask:0 linkType:0];
}

- (NSString *)shortName
{
	return shortName;
}

- (NSString *)longName
{
	return longName;
}

- (BOOL)promisc
{
	return promisc;
}

- (BOOL)loopback
{
	return loopback;
}

- (uint32_t)netmask
{
	return netmask;
}

- (int)linkType
{
	return linkType;
}

- (NSString *)description
{
	return [NSString stringWithFormat:@"%@ (%@)", shortName, longName];
}

- (void)dealloc
{
	[shortName release];
	[longName release];
	[super dealloc];
}

@end
