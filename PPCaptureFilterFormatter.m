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
#include <net/bpf.h>
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

	if([filter filterProgramForLinkType:DLT_EN10MB] == nil) {
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
    // If getObjectValue failed then anObject will be a string
    if([anObject isKindOfClass:[NSString class]])
	    return anObject;
    return nil;
}

- (BOOL)isPartialStringValid:(NSString **)partialStringPtr
    proposedSelectedRange:(NSRangePointer)proposedSelRangePtr
    originalString:(NSString *)origString
    originalSelectedRange:(NSRange)origSelRange
    errorDescription:(NSString **)error
{
    // This seems to be the only way to get Cocoa to accept the partial string
    // as the `replacement'. If you don't do this then it doesn't accept any
    // text at all.
    *partialStringPtr = [NSString stringWithString:*partialStringPtr];
    id unused;
    return [self getObjectValue:&unused forString:*partialStringPtr errorDescription:error];
}

@end
