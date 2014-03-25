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

#ifndef PP_STREAM_COMPARE_H_
#define PP_STREAM_COMPARE_H_

#include <sys/types.h>
#include <objc/objc.h>

#include "pkt_compare.h" /* XXX mem_compare needs its own header */

NSComparisonResult stream_compare(id stream1, id stream2, void *context);

#endif
