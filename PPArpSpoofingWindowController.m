
#include "PPArpSpoofingWindowController.h"
#include "MyDocument.h"
#include "PacketCaptureWindowController.h"

#import <AppKit/NSButton.h>
#import <AppKit/NSProgressIndicator.h>
#import <AppKit/NSTextField.h>
#import <AppKit/NSWorkSpace.h>
#import <Foundation/NSArray.h>
#import <Foundation/NSString.h>
#import <Foundation/NSURL.h>

@interface PPArpSpoofingTableItem : NSObject
{
    @public NSComboBoxCell* hostAComboBox_;
    @public NSComboBoxCell* hostBComboBox_;
    @public NSButton* enabledButton_;
}
@end

@implementation PPArpSpoofingTableItem

- (id)init
{
    if((self = [super init]) != nil) {
        hostAComboBox_ = [[NSComboBoxCell alloc] init];
        hostBComboBox_ = [[NSComboBoxCell alloc] init];
        enabledButton_ = [[NSButton alloc] init];
    }
    return self;
}

- (void)dealloc
{
    [hostAComboBox_ release];
    [hostBComboBox_ release];
    [enabledButton_ release];
    [super dealloc];
}

@end

@implementation PPArpSpoofingWindowController

- (id)init
{
    if((self = [super initWithWindowNibName:@"PPArpSpoofingWindow"]) != nil) {
        targetsArray_ = [[NSMutableArray alloc] init];
        neighbouringHostsArray_ = [[NSMutableArray alloc] init];
        [neighbouringHostsArray_ addObject:@"One"];
        [neighbouringHostsArray_ addObject:@"Two"];
        [neighbouringHostsArray_ addObject:@"Three"];
    }
    return self;
}

- (void)dealloc
{
    [targetsArray_ release];
    [neighbouringHostsArray_ release];
    [super dealloc];
}

- (IBAction)startSpoofingButton:(id)sender
{
    NSMutableArray* targets = [[NSMutableArray alloc] init];

    for (NSInteger i = 0; i < [targetsArray_ count]; ++i)
    {
        PPArpSpoofingTableItem* item = [targetsArray_ objectAtIndex:i];
        if ([item->enabledButton_ state] == NSOnState)
            [targets addObject:item];
    }

    if ([targets count] > 0)
    {
        [progressIndicator_ startAnimation:nil];
        [statusTextField_
            setStringValue:[NSString
                stringWithFormat:@"Spoofing %lu target%s...", 
                    [targets count], [targets count] > 1 ? "s" : ""]];
    }
    else
    {
        [progressIndicator_ stopAnimation:nil];
        [statusTextField_ setStringValue:@"No targets specified!"];
    }

    [targets release];
}

- (IBAction)stopSpoofingButton:(id)sender
{
    [progressIndicator_ stopAnimation:nil];
    [statusTextField_ setStringValue:@""];
}

- (IBAction)scanLocalSubnetButton:(id)sender
{
    [progressIndicator_ startAnimation:nil];
    [statusTextField_ setStringValue:@"Scanning..."];
}

- (IBAction)addTargetsTableRow:(id)sender
{
    PPArpSpoofingTableItem* item = [[PPArpSpoofingTableItem alloc] init];
    [item->hostAComboBox_ setUsesDataSource:YES];
    [item->hostBComboBox_ setUsesDataSource:YES];
    [item->hostAComboBox_ setDataSource:self];
    [item->hostBComboBox_ setDataSource:self];
    [targetsArray_ addObject:item];
    [targetsTableView_ noteNumberOfRowsChanged];
}

- (IBAction)removeTargetsTableRow:(id)sender
{
    if (
        [targetsArray_ count] > 0 &&
        [targetsTableView_ selectedRow] != -1)
    {
        [targetsArray_ removeObjectAtIndex:[targetsTableView_ selectedRow]];
        [targetsTableView_ noteNumberOfRowsChanged];
    }
}

- (IBAction)helpButton:(id)sender
{
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"http://packetpeeper.org/arp-spoofing-help"]];
}

- (NSString *)windowTitleForDocumentDisplayName:(NSString *)displayName
{
	return
        [NSString stringWithFormat:@"%@ - %@ - ARP Spoofing", displayName,
        [[self document] interface]];
}

- (void)setDocumentEdited:(BOOL)flag
{
	return;
}

- (NSResponder *)nextResponder
{
	return [[self document] packetCaptureWindowController];
}

// NSTableView data-source methods

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView
{
    return [targetsArray_ count];
}

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)rowIndex
{
    if ([[tableColumn identifier] isEqualToString:@"HostA"])
    {
        PPArpSpoofingTableItem* item = [targetsArray_ objectAtIndex:rowIndex];
        return item->hostAComboBox_;
    }
    else if ([[tableColumn identifier] isEqualToString:@"HostB"])
    {
        PPArpSpoofingTableItem* item = [targetsArray_ objectAtIndex:rowIndex];
        return item->hostBComboBox_;
    }
    else if ([[tableColumn identifier] isEqualToString:@"Enabled"])
    {
        PPArpSpoofingTableItem* item = [targetsArray_ objectAtIndex:rowIndex];
        return item->enabledButton_;
    }
    return nil;
}

- (void)tableView:(NSTableView *)aTableView setObjectValue:(id)anObject forTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)rowIndex
{
    if ([[tableColumn identifier] isEqualToString:@"HostA"] && [[anObject class] isSubclassOfClass:[NSString class]])
    {
        PPArpSpoofingTableItem* item = [targetsArray_ objectAtIndex:rowIndex];
        const NSUInteger hostIndex = [neighbouringHostsArray_ indexOfObject:anObject];
        [item->hostAComboBox_ selectItemAtIndex:hostIndex];
        [item->hostAComboBox_ setObjectValue:anObject];
    }
    else if ([[tableColumn identifier] isEqualToString:@"HostB"] && [[anObject class] isSubclassOfClass:[NSString class]])
    {
        PPArpSpoofingTableItem* item = [targetsArray_ objectAtIndex:rowIndex];
        const NSUInteger hostIndex = [neighbouringHostsArray_ indexOfObject:anObject];
        [item->hostBComboBox_ selectItemAtIndex:hostIndex];
        [item->hostBComboBox_ setObjectValue:anObject];
    }
    else if ([[tableColumn identifier] isEqualToString:@"Enabled"] && [[anObject class] isSubclassOfClass:[NSValue class]])
    {
        PPArpSpoofingTableItem* item = [targetsArray_ objectAtIndex:rowIndex];
        [item->enabledButton_ setState:[anObject intValue]];
    }
}

// NSComboBoxCell data-source methods

- (id)comboBoxCell:(NSComboBoxCell *)aComboBoxCell objectValueForItemAtIndex:(NSInteger)index
{
    return [neighbouringHostsArray_ objectAtIndex:index];
}

- (NSInteger)numberOfItemsInComboBoxCell:(NSComboBoxCell *)aComboBoxCell
{
    return [neighbouringHostsArray_ count];
}

@end

