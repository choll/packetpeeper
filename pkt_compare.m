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

#include "Packet.h"
#include "ColumnIdentifier.h"
#include "PPPacketUIAdditons.h"
#include "pkt_compare.h"

NSComparisonResult pkt_compare(id pkt1, id pkt2, void *context)
{
	return [(Packet *)pkt1 compare:pkt2 withColumn:(ColumnIdentifier *)context];
}

NSComparisonResult mem_compare(const void *b1, const void *b2, size_t len)
{
	size_t i;

	for(i = 0; i < len; ++i) {
		if(((uint8_t *)b1)[i] > ((uint8_t *)b2)[i])
			return NSOrderedDescending;

		if(((uint8_t *)b1)[i] < ((uint8_t *)b2)[i])
			return NSOrderedAscending;
	}

	return NSOrderedSame;
}

