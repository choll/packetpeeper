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

#include <Python.h>
#import <Foundation/NSObject.h>
#import <Foundation/NSBundle.h>
#import <Foundation/NSFileManager.h>
#import <Foundation/NSString.h>
#import <Foundation/NSPathUtilities.h>
#import <Foundation/NSArray.h>
#include "TCPDecode.h"
#include "UDPDecode.h"
#include "Describe.h"
#include "PPPyDecoderPlugin.h"
#include "PPDecoderPlugin.h"
#include "PPPluginManager.h"

static PPPluginManager *sharedPluginManager = nil;

@implementation PPPluginManager

- (id)init
{
	if((self = [super init]) != nil) {
		plugins = [[NSMutableArray alloc] init];
		[self loadPluginDecoders];
	}
	return self;
}

+ (PPPluginManager *)sharedPluginManager
{
	if(sharedPluginManager == nil)
		sharedPluginManager = [[PPPluginManager alloc] init];

	return sharedPluginManager;
}

- (NSArray *)pluginsList
{
	return plugins;
}

- (id <PPDecoderPlugin>)pluginWithLongName:(NSString *)longName
{
	unsigned int i;

	for(i = 0; i < [plugins count]; ++i) {
		if([longName isEqualToString:[[plugins objectAtIndex:i] longName]])
			return [plugins objectAtIndex:i];
	}

	return nil;
}

- (id <PPDecoderPlugin>)pluginDecoderForDecoder:(id <Describe>)decoder
{
	unsigned int srcPort;
	unsigned int dstPort;
	NSString *shortName;
	unsigned int i;

	/* srcPort/dstPort methods should probably be part of a protocol... */

	if(decoder == nil)
		return nil;

	if([decoder isMemberOfClass:[TCPDecode class]]) {
		srcPort = [(TCPDecode *)decoder srcPort];
		dstPort = [(TCPDecode *)decoder dstPort];
	} else if([decoder isMemberOfClass:[UDPDecode class]]) {
		srcPort = [(UDPDecode *)decoder srcPort];
		dstPort = [(UDPDecode *)decoder dstPort];
	} else
		return nil;

	shortName = [[decoder class] shortName];

	for(i = 0; i < [plugins count]; ++i) {
		id <PPDecoderPlugin> plugin;

		plugin = [plugins objectAtIndex:i];

		if([plugin canDecodeProtocol:shortName port:srcPort] ||
		   [plugin canDecodeProtocol:shortName port:dstPort])
			return plugin;
	}

	return nil;
}

- (void)addPluginDecoder:(id <PPDecoderPlugin>)plugin
{
	[plugins addObject:plugin];
}

- (void)loadPluginDecoders
{
	NSArray *files;
	unsigned int i;

	files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[[NSBundle mainBundle] builtInPlugInsPath] error:nil];

	for(i = 0; i < [files count]; ++i) {
		NSString *path;

		path = [files objectAtIndex:i];
		[self addPluginDecoderForFile:path];
	}
}

+ (id <PPDecoderPlugin>)pluginDecoderForFile:(NSString *)path
{
	NSString *relativePath;
	id <PPDecoderPlugin> ret;

	relativePath = [path lastPathComponent];
	ret = nil;

	if([[relativePath pathExtension] isEqualToString:@"py"])
		ret = [[PPPyDecoderPlugin alloc] initWithModule:[relativePath stringByDeletingPathExtension]];

	return [ret autorelease];
}

- (BOOL)addPluginDecoderForFile:(NSString *)path
{
	id <PPDecoderPlugin> plugin;

	if((plugin = [PPPluginManager pluginDecoderForFile:path]) == nil)
		return NO;

	[self addPluginDecoder:plugin];
	return YES;
}

- (void)dealloc
{
	[plugins release];
	[super dealloc];
}

@end
