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

#ifndef PACKETPEEPER_DATEFORMAT_H
#define PACKETPEEPER_DATEFORMAT_H

@class NSString;
@class NSDate;

/* NSCalendarDate cannot store milliseconds (or anything less than a second)
   so NSDate is used, however NSDate lacks formatting methods, so we use this */

@interface NSDate (DateFormat)

- (NSString*)descriptionWithFormat:(NSString*)format;

@end

#endif
