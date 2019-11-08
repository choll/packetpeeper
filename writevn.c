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

#include "writevn.h"
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/*
	Wrapper around writev, as writev might write less than was specified
	(depending on what we're writing to), this is not an error, so writevn will
	continue writing the remaining data. Unlike writev, writevn may modify the
	members of the iov array. See writev(2).
*/
ssize_t writevn(int fd, struct iovec* iov, int iovcnt)
{
    size_t nleft;
    ssize_t nwritten;
    ssize_t ret;
    unsigned int i;

    for (i = 0, nleft = 0; i < iovcnt; ++i)
        nleft += iov[i].iov_len;

    ret = nleft;

    while (nleft > 0)
    {
        if ((nwritten = writev(fd, iov, iovcnt)) <= 0)
            return nwritten;

        nleft -= nwritten;

        /* return early to avoid unneeded updating of iov */
        if (nleft == 0)
            break;

        for (i = 0; i < iovcnt; ++i)
        {
            if (nwritten >= iov[i].iov_len)
            {
                nwritten -= iov[i].iov_len;
            }
            else
            {
                iov[i].iov_len -= nwritten;
                iov[i].iov_base = (uint8_t*)iov[i].iov_base + nwritten;
                break;
            }
        }
        iov += i;
    }

    return ret;
}
