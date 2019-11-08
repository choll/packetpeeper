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

#include "PPBPFProgram.h"
#import <Foundation/NSArchiver.h>
#import <Foundation/NSObject.h>
#include <net/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>

@implementation PPBPFProgram

- (id)initWithProgram:(struct bpf_program*)program
{
    if ((self = [super init]) != nil)
    {
        if (program == NULL || program->bf_len == 0)
            goto err;

        m_program.bf_len = program->bf_len;

        if ((m_program.bf_insns =
                 malloc(m_program.bf_len * sizeof(struct bpf_insn))) == NULL)
            goto err;

        memcpy(
            m_program.bf_insns,
            program->bf_insns,
            m_program.bf_len * sizeof(struct bpf_insn));
    }
    return self;

err:
    [super dealloc];
    return nil;
}

- (const struct bpf_program*)program
{
    return &m_program;
}

- (void)encodeWithCoder:(NSCoder*)encoder
{
    [encoder encodeValueOfObjCType:@encode(unsigned int) at:&m_program.bf_len];
    [encoder encodeArrayOfObjCType:@encode(struct bpf_insn)
                             count:m_program.bf_len
                                at:m_program.bf_insns];
}

- (id)initWithCoder:(NSCoder*)decoder
{
    if ((self = [super init]) != nil)
    {
        [decoder decodeValueOfObjCType:@encode(unsigned int)
                                    at:&m_program.bf_len];
        if ((m_program.bf_insns =
                 malloc(m_program.bf_len * sizeof(struct bpf_insn))) == NULL)
            goto err;
        [decoder decodeArrayOfObjCType:@encode(struct bpf_insn)
                                 count:m_program.bf_len
                                    at:m_program.bf_insns];
    }
    return self;

err:
    [super dealloc];
    return nil;
}

- (void)dealloc
{
    if (m_program.bf_insns != NULL)
        free(m_program.bf_insns);
    [super dealloc];
}

@end
