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

#ifndef _STRFUNCS_H_
#define _STRFUNCS_H_

@class NSString;

NSString* binstr(const void* data, unsigned int bits);
NSString* hexstr(const void* data, size_t size);
NSString* etherstr(const void* data, size_t size);
NSString* ipaddrstr(const void* data, size_t size);

#endif /* _STRFUNCS_H_ */
