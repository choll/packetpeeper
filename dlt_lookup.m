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

#include "dlt_lookup.h"
#include "EthernetDecode.h"
#include "IPV4Decode.h"
#include "LoopbackDecode.h"
#include "PPPDecode.h"
#include "PPRVIDecode.h"
#include "pktap.h"
#include <net/bpf.h>
#include <objc/objc.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>

/*
	Not strictly part of the 'Decoders' set of objects/functions,
	exists to 'kickstart' the demultiplexing of the packet by
	returning the protocol value for a bpf DLT_XXX value.
*/

Class dlt_lookup(int dlt)
{
    switch (dlt)
    {
    case DLT_PKTAP:
        return [PPRVIDecode class];
    case DLT_NULL:
        return [LoopbackDecode class];
    case DLT_EN10MB:
        return [EthernetDecode class];
    case DLT_PPP:
        return [PPPDecode class];
    /* bpf.h describes as 'raw IP', assumed to be IPV4 */
    case DLT_RAW:
        return [IPV4Decode class];
    }

    return Nil;
}
