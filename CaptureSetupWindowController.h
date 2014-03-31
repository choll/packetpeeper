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

#ifndef _CAPTURESETUPWINDOWCONTROLLER_H_
#define _CAPTURESETUPWINDOWCONTROLLER_H_

/* CaptureSetupWindowController */

#include "PPCaptureFilterWindowController.h"

@class NSArray;
@class NSPopUpButton;
@class NSButton;
@class NSTextField;
@class NSStepper;
@class NSDatePicker;
@class MyDocument;
@class NSSlider;

@interface CaptureSetupWindowController : PPCaptureFilterWindowController
{
	/* basic settings controlls */
	IBOutlet NSPopUpButton *interfacePopUp;
	IBOutlet NSButton *promiscuousCheckBox;
	IBOutlet NSButton *realTimeCheckBox;

	/* advanced settings controlls */
	IBOutlet NSSlider *bufferLengthSlider;
	IBOutlet NSTextField *updateFrequencyTextField;
	IBOutlet NSTextField *stopPacketsTextField;
	IBOutlet NSDatePicker *stopTimeDatePicker;
	IBOutlet NSTextField *stopDataTextField;
	IBOutlet NSPopUpButton *stopConditionPopUp;

	IBOutlet NSButton *stopPacketsCheckBox;
	IBOutlet NSButton *stopTimeCheckBox;
	IBOutlet NSButton *stopDataCheckBox;

	NSArray *interfaces;

}

/* basic settings actions */
- (IBAction)interfacePopUpSelected:(id)sender;
- (IBAction)startButtonPressed:(id)sender;
- (IBAction)cancelButtonPressed:(id)sender;

/* advanced settings actions */
- (IBAction)stopConditionCheckBox:(id)sender;

- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo;

@end

#endif
