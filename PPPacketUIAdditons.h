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

#ifndef PPPacketUIAdditions_H_
#define PPPacketUIAdditions_H_

#include "ColumnIdentifier.h"

#define PACKET_COLUMN_INDEX_NUMBER		0
#define PACKET_COLUMN_INDEX_DATE		1

@class Packet;
@class PPBPFProgram;
@protocol PPDecoderPlugin;

@interface Packet (PPPacketUIAdditions) <OutlineViewItem, ColumnIdentifier>

- (void)processPlugins;
- (NSString *)protocols; /* protocol short names in reverse order */
- (NSString *)info; /* information strings in reverse order */
- (NSComparisonResult)compare:(Packet *)packet withColumn:(ColumnIdentifier *)column;
- (NSString *)stringForColumn:(ColumnIdentifier *)columnIdentifier;
- (id)decoderForPlugin:(id <PPDecoderPlugin>)plugin;
- (BOOL)runFilterProgram:(PPBPFProgram *)filterProgram;

@end

#endif
