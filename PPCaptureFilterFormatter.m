/*
 * Packet Peeper
 * Copyright 2008 Chris E. Holloway
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
#import <Foundation/NSObject.h>
#import <Foundation/NSString.h>
#include "PPCaptureFilter.h"
#include "PPCaptureFilterFormatter.h"

@implementation PPCaptureFilterFormatter

- (BOOL)getObjectValue:(id *)anObject forString:(NSString *)string errorDescription:(NSString **)error
{
	PPCaptureFilter *filter;

	if([string length] < 1) {	
		*anObject = nil;
		return YES;
	}

	if((filter = [[PPCaptureFilter alloc] initWithTCPDumpFilter:string]) == nil)
		return NO;

	if([filter filterProgramForLinkType:0] == nil) {
		NSString *temp;

		if(error != NULL) {
			temp = [[filter errorString] retain];
			*error = temp;
			[temp autorelease];
		}

		[filter release];
		return NO;
	}

	[filter autorelease];
	*anObject = filter;

	return YES;
}

- (NSString *)stringForObjectValue:(id)anObject
{
	if([anObject isKindOfClass:[PPCaptureFilter class]])
		return [anObject filterText];

	return nil;
}

@end
