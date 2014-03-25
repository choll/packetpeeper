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

#import <Foundation/NSString.h>
#import <Foundation/NSCoder.h>
#include "PPPluginManager.h"
#include "PPDecoderPlugin.h"
#include "ColumnIdentifier.h"


@implementation ColumnIdentifier

- (id)initWithDecoder:(Class)decoderVal index:(unsigned int)indexVal longName:(NSString *)longNameVal shortName:(NSString *)shortNameVal
{
	if((self = [super init]) != nil) {
		decoder = decoderVal;
		plugin = nil;
		index = indexVal;
		longName = [longNameVal retain];
		shortName = [shortNameVal retain];
	}
	return self;
}

- (id)initWithPlugin:(id <PPDecoderPlugin>)pluginVal index:(unsigned int)indexVal longName:(NSString *)longNameVal shortName:(NSString *)shortNameVal
{
	if((self = [super init]) != nil) {
		decoder = Nil;
		plugin = [pluginVal retain];
		index = indexVal;
		longName = [longNameVal retain];
		shortName = [shortNameVal retain];
	}
	return self;
}

- (BOOL)isEqual:(id)anObject
{
	if(![anObject isMemberOfClass:[ColumnIdentifier class]])
		return NO;

	return (decoder == [anObject decoder] && index == [anObject index]);
}

- (Class)decoder
{
	return decoder;
}

- (id <PPDecoderPlugin>)plugin
{
	return plugin;
}

- (unsigned int)index
{
	return index;
}

- (NSString *)longName
{
	return longName;
}

- (NSString *)shortName
{
	return shortName;
}

- (NSString *)identifier
{
    return longName;
}

/* NSCoding protocol methods */

- (void)encodeWithCoder:(NSCoder *)coder
{
	BOOL isPlugin;

	if(plugin != nil) {
		isPlugin = YES;
		[coder encodeValueOfObjCType:@encode(BOOL) at:&isPlugin];
		[coder encodeObject:[plugin longName]];
	} else {
		isPlugin = NO;
		[coder encodeValueOfObjCType:@encode(BOOL) at:&isPlugin];
		[coder encodeObject:NSStringFromClass(decoder)];
	}

	[coder encodeValueOfObjCType:@encode(unsigned int) at:&index];
	[coder encodeObject:longName];
	[coder encodeObject:shortName];
}

- (id)initWithCoder:(NSCoder *)coder
{
	BOOL isPlugin;

	if((self = [super init]) != nil) {
		[coder decodeValueOfObjCType:@encode(BOOL) at:&isPlugin];

		if(isPlugin) {
			NSString *pluginName;

			pluginName = [coder decodeObject];
			if((plugin = [[PPPluginManager sharedPluginManager] pluginWithLongName:pluginName]) == nil) {
				[super dealloc];
				return nil;
			}
		} else {
			if((decoder =  NSClassFromString([coder decodeObject])) == nil) {
				[super dealloc];
				return nil;
			}
		}

		[coder decodeValueOfObjCType:@encode(unsigned int) at:&index];
		longName = [[coder decodeObject] retain];
		shortName = [[coder decodeObject] retain];
	}
	return self;
}

- (NSString *)description
{
	return [NSString stringWithFormat:@"<%@: shortName='%@', longName='%@', plugin='%@', decoder='%@', index=%u>",
			NSStringFromClass([self class]), shortName, longName, plugin, NSStringFromClass(decoder), index];
}

- (void)dealloc
{
	[plugin release];
	[longName release];
	[shortName release];
	[super dealloc];
}

@end
