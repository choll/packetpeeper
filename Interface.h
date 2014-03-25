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

#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#import <Foundation/NSObject.h>

@class NSString;
@class NSArray;

/*
	TODO: Link up with MAC lookup class to give the card name manufacturer.
		  Although, this might be ok on a PC, on a mac its always going to
		  be Apple...
*/

@interface Interface : NSObject
{
	NSString *shortName;	/* interfaces short name, eg en0 */
	NSString *longName;		/* place holder for the interfaces long name */
	BOOL promisc;			/* is promiscuous mode enabled */
	BOOL loopback;			/* is the interface a loopback net */
	uint32_t netmask;		/* netmask of interface */
	int linkType;
}

+ (NSArray *)liveInterfaces;
- (id)initWithShortName:(NSString *)shortNameVal longName:(NSString *)longNameVal promisc:(BOOL)promiscVal loopback:(BOOL)loopbackVal netmask:(uint32_t)netmaskVal linkType:(int)linkTypeVal;
- (NSString *)shortName;
- (NSString *)longName;
- (BOOL)promisc;
- (BOOL)loopback;
- (uint32_t)netmask;
- (int)linkType;

@end

#endif /* _INTERFACE_H_ */
