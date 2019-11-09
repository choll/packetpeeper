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

#ifndef _MYDOCUMENTCONTROLLER_H_
#define _MYDOCUMENTCONTROLLER_H_

#import <AppKit/NSDocumentController.h>
#include <Security/Authorization.h>
#include <sys/un.h>

@interface MyDocumentController : NSDocumentController
{
    AuthorizationRef auth_ref;
    struct sockaddr_un servaddr;
    unsigned int ndocs;
    int listenfd;
    BOOL sighand; /* records if the signal handler has been installed */
}

- (IBAction)terminate:(id)sender;
- (IBAction)newDocument:(id)sender;

/* the folowing are private methods */
- (BOOL)createAuthRef;
- (BOOL)listenSetup;
- (void)freeAuthRef;

- (void)cancelHelper;
- (int)launchHelper;

@end

#endif
