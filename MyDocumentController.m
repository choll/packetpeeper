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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/select.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#import <Foundation/NSString.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSBundle.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSWindow.h>
#import <AppKit/NSOpenPanel.h>
#include "CaptureSetupWindowController.h"
#include "PPCaptureFilterWindowController.h"
#include "PPProgressWindowController.h"
#include "MyDocument.h"
#include "socketpath.h"
#include "ErrorStack.h"
#include "MyDocumentController.h"

#ifdef LOCAL_BIN_HELPER_PATH
#define HELPER_PATH "/usr/local/bin/PacketPeeperHelper"
#else
#define HELPER_PATH [[[NSBundle mainBundle] pathForAuxiliaryExecutable:@"PacketPeeperHelper"] UTF8String]
#endif

@implementation MyDocumentController

- (id)init
{
	if((self = [super init]) != nil) {
		(void)unlink(SOCKETPATH);
		auth_ref = NULL;
		listenfd = -1;
		sighand = NO;
	}
	return self;
}

- (IBAction)terminate:(id)sender
{
	NSArray *windows;
	unsigned int i;

	windows = [NSApp windows];

	for(i = 0; i < [windows count]; ++i) {
		if([[[windows objectAtIndex:i] windowController] isMemberOfClass:[CaptureSetupWindowController class]] ||
		   [[[windows objectAtIndex:i] windowController] isMemberOfClass:[PPCaptureFilterWindowController class]] ||
		   [[[windows objectAtIndex:i] windowController] isMemberOfClass:[PPProgressWindowController class]]) {
			[[[windows objectAtIndex:i] windowController] cancelButtonPressed:sender];
		}
	}

	[NSApp terminate:sender];
}

- (void)removeDocument:(NSDocument *)document
{
	[super removeDocument:document];
}

- (id)openDocumentWithContentsOfURL:(NSURL *)absoluteURL display:(BOOL)displayDocument error:(NSError **)outError
{
	return [super openDocumentWithContentsOfURL:absoluteURL display:displayDocument error:outError];
}

- (IBAction)newDocument:(id)sender
{
	AuthorizationItem items = {kAuthorizationRightExecute, 0, NULL, 0};	/* right to exec as root */
	AuthorizationRights rights = {1, &items};

	if(![self createAuthRef])
		return; /* createAuthRef creates an ErrorStack */

	/* preauthorize */
	if(AuthorizationCopyRights(auth_ref, &rights, kAuthorizationEmptyEnvironment,
				 (kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize |
				 kAuthorizationFlagExtendRights), NULL) != errAuthorizationSuccess) {
		/* user failed to authenticate, release authentication reference */
		[self freeAuthRef];
		return;
	}
	++ndocs;
	[super newDocument:sender];
	[[self currentDocument] displaySetupSheet];
}

- (BOOL)createAuthRef
{
	/* initialize the authorization reference */
	if(!auth_ref) {
		if(AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &auth_ref) != errAuthorizationSuccess) {
			[[ErrorStack sharedErrorStack] pushError:@"Failed to obtain authorization reference" lookup:Nil code:0 severity:ERRS_ERROR];
			return NO;
		}
	}
	return YES;
}

- (BOOL)listenSetup
{
	if(listenfd == -1) {
		mode_t oldmask;

		if(!sighand) {
			struct sigaction act;

			act.sa_handler = SIG_IGN;
			sigemptyset(&act.sa_mask);
			act.sa_flags = 0;

			/* only errors possible are those for supplying invalid arguments */
			(void)sigaction(SIGPIPE, &act, NULL);
			sighand = YES;
		}

		if((listenfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
			return NO;

		servaddr.sun_family = AF_LOCAL;
		strlcpy(servaddr.sun_path, SOCKETPATH, sizeof(servaddr.sun_path));

		oldmask = umask(S_IXUSR|S_IRWXG|S_IRWXO);

		if(bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
			(void)close(listenfd);
			listenfd = -1;
			[[ErrorStack sharedErrorStack] pushError:@"Could not bind socket" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
			return NO;
		}

		(void)umask(oldmask);

		if(listen(listenfd, 5) == -1) { // XXX config.h?
			(void)close(listenfd);
			listenfd = -1;
			[[ErrorStack sharedErrorStack] pushError:@"Could not listen on socket" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
			return NO;
		}
	}
	return YES;
}

- (void)freeAuthRef
{
	if(auth_ref) {
		(void)AuthorizationFree(auth_ref, kAuthorizationFlagDefaults);
		auth_ref = NULL;
	}
}

- (void)cancelHelper
{
	if(ndocs == 1)
		[self freeAuthRef];

	if(ndocs)
		--ndocs;
}

- (int)launchHelper
{
	int connfd;
	struct fd_set fdset;
	struct timeval timeout;

    // XXX WONTFIX
    // For now anyway. EvenBetterAuthorizationSample describes how to use the new API.
    // Problem is, once the privileged tool has been installed setuid root, can anyone
    // execute the tool? That would not be acceptable from a security point of view.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	if(AuthorizationExecuteWithPrivileges(auth_ref, HELPER_PATH, kAuthorizationFlagDefaults, NULL, NULL) != errAuthorizationSuccess) {
		[[ErrorStack sharedErrorStack] pushError:@"Could not execute helper tool" lookup:Nil code:0 severity:ERRS_ERROR];
		return -1;
	}
#pragma clang diagnostic pop

	if(ndocs == 1)
		[self freeAuthRef];

	if(ndocs)
		--ndocs;

	if(![self listenSetup])
		return -1; /* listenSetup creates an ErrorStack */

	timeout.tv_sec = 60; // XXX config.h
	timeout.tv_usec = 0;

	FD_ZERO(&fdset);
	FD_SET(listenfd, &fdset);

	switch(select(listenfd + 1, &fdset, NULL, NULL, &timeout)) {
		/* error condition */
		case -1:
			[[ErrorStack sharedErrorStack] pushError:@"Error when waiting for helper tool to connect" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
			return -1;
			/* NOTREACHED */

		/* timeout occured */
		case 0:
			[[ErrorStack sharedErrorStack] pushError:@"Timed out waiting for helper tool to connect" lookup:Nil code:0 severity:ERRS_ERROR];
			return -1;
			/* NOTREACHED */
	}

	/* listenfd is known to be ready */
	if((connfd = accept(listenfd, NULL, NULL)) == -1) {
		[[ErrorStack sharedErrorStack] pushError:@"Could not accept connection on socket" lookup:[PosixError class] code:errno severity:ERRS_ERROR];
		return -1;
	}

	return connfd;
}

- (void)dealloc
{
	if(listenfd == -1)
		(void)close(listenfd);
	(void)unlink(SOCKETPATH);
	[self freeAuthRef];
	[super dealloc];
}

@end
