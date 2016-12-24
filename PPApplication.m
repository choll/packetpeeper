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

#include <stdlib.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSDictionary.h>
#import <Foundation/NSString.h>
#import <Foundation/NSBundle.h>
#import <Foundation/NSPredicate.h>
#import <AppKit/NSDocumentController.h>
#import <AppKit/NSWindow.h>
#import <AppKit/NSDocument.h>
#import <AppKit/NSPanel.h>
#import <AppKit/NSWindowController.h>
#include "PacketCaptureWindowController.h"
#include "MyDocument.h"
#include "PPApplication.h"

/*
	TODO: Change this to call waitForWorkerThread on each document, or ditch it
	all if we can make the document detect if its save methods are being called
	due to a document close, in which case it would call waitForWorkerThread
	itself.
*/

@implementation PPApplication

- (id)init
{
	if((self = [super init]) != nil) {
		documentsPendingClose = [[NSMutableArray alloc] init];
		terminatePending = NO;
		reviewDocuments = nil;
		[[NSNotificationCenter defaultCenter] addObserver:self
											  selector:@selector(documentSaveOperationCompleted:)
											  name:PPDocumentSaveOperationSucceededNotification
											  object:nil];
		[[NSNotificationCenter defaultCenter] addObserver:self
											  selector:@selector(documentSaveOperationCompleted:)
											  name:PPDocumentSaveOperationFailedNotification
											  object:nil];
	}
	return self;
}

- (void)documentSaveOperationCompleted:(NSNotification *)note
{
	NSDocument *document;

	document = [note object];

	if([documentsPendingClose containsObject:document]) {
		[documentsPendingClose removeObject:document];

		if([[note name] isEqualToString:PPDocumentSaveOperationSucceededNotification]) {
			[[note object] close];
		} else if([[note name] isEqualToString:PPDocumentSaveOperationFailedNotification]) {
			/* if a save failed, cancel the quit */
			terminatePending = NO;
			[reviewDocuments release];
			reviewDocuments = nil;
		}

		if(terminatePending && [reviewDocuments count] < 1 && [documentsPendingClose count] < 1) {
			/* quit if this was the last document pending close and no documents are pending review */
			terminatePending = NO;
			[reviewDocuments release];
			reviewDocuments = nil;
			[self exit];
		}
	}
}

#if 0
// XXX THIS IS BECAUSE OF ASYNC SAVING - NEED TO GET RID OF THIS AS NSDOCUMENT CAN DO ASYNC NOW
- (BOOL)sendAction:(SEL)action to:(id)target from:(id)sender
{
	if(action == @selector(_close:) &&
	  [target isMemberOfClass:[NSWindow class]] &&
	  [[target windowController] isMemberOfClass:[PacketCaptureWindowController class]]) {
		PacketCaptureWindowController *windowController;
		MyDocument *document;

		windowController = [target windowController];
		document = [windowController document];

		[document shouldCloseWindowController:windowController delegate:self shouldCloseSelector:@selector(document:shouldClose:contextInfo:) contextInfo:NULL];
		return YES;
	}

	return [super sendAction:action to:target from:sender];
}
#endif

- (void)document:(MyDocument *)document shouldClose:(BOOL)shouldClose contextInfo:(void *)contextInfo
{
	if(shouldClose) {
		if([document isSaveOperationInProgress]) {
			/* This only makes sense in the context of threaded document saves, and is
			   pretty unclean. The save is in progress so we need to prevent the document
			   from becoming dirty again. Packets are read on the same thread this is called
			   on though, so there is no race condition--no packets can be read between the
			   thread being spawned and this method being called */
			[document stopCapture];
			[documentsPendingClose addObject:document];
		} else {
			[document close]; /* user asked not to save, or saved in a document type not using threads */
			if(terminatePending && [reviewDocuments count] < 2 && [documentsPendingClose count] < 1) {
				/* quit if this was the last document being reviewed and no documents are pending close */
				terminatePending = NO;
				[reviewDocuments release];
				reviewDocuments = nil;
				[self exit];
			}
		}
	} else { /* else user cancelled */
		terminatePending = NO;
		[reviewDocuments release];
		reviewDocuments = nil;
	}

	if(terminatePending) {
		if([reviewDocuments count] > 1) {
			[reviewDocuments removeObjectAtIndex:0];
			[[reviewDocuments objectAtIndex:0] canCloseDocumentWithDelegate:self shouldCloseSelector:@selector(document:shouldClose:contextInfo:) contextInfo:NULL];
		} else if([reviewDocuments count] == 1) {
			[reviewDocuments removeObjectAtIndex:0]; /* remove the last document */
		}
	}
}


- (BOOL)_shouldTerminate
{
	/* this method returns NO to cancel a logoff/shutdown. If YES is returned,
	   it seems that a timer is installed which fires immediately, calling
	   - (void)_terminateSendShould:(BOOL)value, which calls terminate:.
	   As we save asynchronously, we can't give any meaningful return value,
	   so just return YES, then do not call super, and wait for terminate:
	   to be called, which will then operate as normal. Only downside is that
	   if the user presses, cancel to a save dialogue, the logoff/shutdown
	   will not be cancelled immediately, but will instead time out--not a big
	   deal. Also if we have several files which take a long time to save,
	   we could cause a cancel due to timeout, no big deal again. */

	return YES;
}

- (void)terminate:(id)sender
{
	NSArray *documents;
	NSString *applicationName;

	if(terminatePending)
		return;

	if([[self delegate] respondsToSelector:@selector(applicationShouldTerminate:)]) {
		NSApplicationTerminateReply shouldTerminate;
		shouldTerminate = [[self delegate] applicationShouldTerminate:self];
		/* replyToApplicationShouldTerminate: might also need overriding, if NSTerminateLater is used in the future */
		if(shouldTerminate == NO || shouldTerminate == NSTerminateCancel || shouldTerminate ==  NSTerminateLater)
			return;
	}

	documents = [[NSDocumentController sharedDocumentController] documents];
	documents = [documents filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"isDocumentEdited == YES"]];

	if([documents count] < 1)
		[self exit];

	applicationName = [[[NSBundle mainBundle] localizedInfoDictionary] objectForKey:(NSString *)kCFBundleNameKey];

	if([documents count] > 1) {
        NSAlert *alert = [[NSAlert alloc] init];

        alert.messageText = [NSString stringWithFormat:@"You have %lu %@ documents with unsaved changes.\n"
                                                       @"Do you want to review these changes before quitting?",
                                                       [documents count], applicationName];
        alert.informativeText = @"If you don't review your documents, all your changes will be lost.";
        [alert addButtonWithTitle:@"Don’t Save"];
        [alert addButtonWithTitle:@"Cancel"];

        const NSModalResponse panelResult = [alert runModal];
        [alert release];

		if(panelResult == NSAlertThirdButtonReturn)
			return; /* user cancelled quit */
		if(panelResult == NSAlertSecondButtonReturn)
			[self exit]; /* user chose to discard changes */
	}

	terminatePending = YES;
	reviewDocuments = [[NSMutableArray alloc] initWithArray:documents];
	[[reviewDocuments objectAtIndex:0] canCloseDocumentWithDelegate:self shouldCloseSelector:@selector(document:shouldClose:contextInfo:) contextInfo:NULL];
}

- (void)exit
{
#if 0
	NSArray *documents;
	NSDocument *currentDocument;
	unsigned int i;

	/* this is what NSApplication does in terminate:, but I can't see any benefit,
	   we only waste time deallocating objects etc */

	documents = [[NSDocumentController sharedDocumentController] documents];

	for(i = 0; i < [documents count]; ++i) {
		currentDocument = [documents objectAtIndex:i];
		[currentDocument close];
	}
#endif
	[[NSNotificationCenter defaultCenter] postNotificationName:NSApplicationWillTerminateNotification object:self];
	exit(EXIT_SUCCESS);
}

- (void)dealloc
{
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	[documentsPendingClose release];
	[super dealloc];
}

@end
