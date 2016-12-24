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

#ifndef PPCAPTUREFILTERWINDOWCONTROLLER_H_
#define PPCAPTUREFILTERWINDOWCONTROLLER_H_

#import <AppKit/NSWindowController.h>
#import <AppKit/NSComboBox.h>
#import <AppKit/NSTextField.h>
#import <AppKit/NSButton.h>

@class NSArray;
@class NSProgressIndicator;
@class PPCaptureFilter;

@interface PPCaptureFilterWindowController : NSWindowController <NSTextFieldDelegate, NSComboBoxDataSource, NSComboBoxDelegate>
{
	NSArray *filters;

	IBOutlet NSTextField *filterTextField;
	IBOutlet NSComboBox *filterNameComboBox;
	IBOutlet NSTextField *filterNetmaskTextField;
	IBOutlet NSTextField *filterErrorTextField;
	IBOutlet NSButton *applyButton;
}

- (PPCaptureFilter *)filter;
- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(NSModalResponse)returnCode contextInfo:(void *)contextInfo;
- (IBAction)saveFilterButtonPressed:(id)sender;
- (IBAction)deleteFilterButtonPressed:(id)sender;
- (IBAction)applyButtonPressed:(id)sender;
- (IBAction)cancelButtonPressed:(id)sender;

@end

#endif
