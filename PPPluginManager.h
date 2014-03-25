/*
 * Packet Peeper
 * Copyright 2007, Chris E. Holloway
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

#ifndef PPPLUGINMANAGER_H_
#define PPPLUGINMANAGER_H_

@class NSObject;
@class NSMutableArray;
@protocol PPDecoderPlugin;
@protocol Describe;

@interface PPPluginManager : NSObject
{
	NSMutableArray *plugins;
}

+ (PPPluginManager *)sharedPluginManager;
- (NSArray *)pluginsList;
- (id <PPDecoderPlugin>)pluginWithLongName:(NSString *)longName;
- (id <PPDecoderPlugin>)pluginDecoderForDecoder:(id <Describe>)decoder;
- (void)addPluginDecoder:(id <PPDecoderPlugin>)plugin;
- (void)loadPluginDecoders;
+ (id <PPDecoderPlugin>)pluginDecoderForFile:(NSString *)path;
- (BOOL)addPluginDecoderForFile:(NSString *)path;

@end

#endif
