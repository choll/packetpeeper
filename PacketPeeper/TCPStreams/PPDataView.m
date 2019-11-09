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

#import "PPDataView.h"
#import <AppKit/NSColor.h>
#import <AppKit/NSFont.h>

/*
 * PPDataView
 */

@implementation PPDataView

- (id)initWithFrame:(NSRect)frame
{
    if ((self = [super initWithFrame:frame]) != nil)
    {
        m_dataSource = nil;
        m_offsetColumnView = nil;
        m_hexDataView = nil;
        m_asciiDataView = nil;
        [[self enclosingScrollView] setPostsFrameChangedNotifications:YES];
    }
    return self;
}

- (void)awakeFromNib
{
    float height;
    float x, y;

    height = NSHeight([self bounds]);

    x = 0.0f;
    y = 0.0f;

#define OFFSET_COLUMN_VIEW_WIDTH 30.0f
#define HEX_DATA_VIEW_WIDTH      60.0f
#define ASCII_DATA_VIEW_WIDTH    30.0f

    m_offsetColumnView = [[PPDataViewOffsetColumn alloc]
        initWithFrame:NSMakeRect(x, y, OFFSET_COLUMN_VIEW_WIDTH, height)];
    [m_offsetColumnView setDataSource:m_dataSource];
    [m_offsetColumnView
        setAutoresizingMask:NSViewHeightSizable | NSViewMaxXMargin];
    [self addSubview:m_offsetColumnView];

    x += OFFSET_COLUMN_VIEW_WIDTH;

    m_hexDataView = [[PPDataViewHexColumn alloc]
        initWithFrame:NSMakeRect(x, y, HEX_DATA_VIEW_WIDTH, height)];
    [m_hexDataView setDataSource:m_dataSource];
    [m_hexDataView setAutoresizingMask:NSViewHeightSizable];
    [self addSubview:m_hexDataView];

    x += HEX_DATA_VIEW_WIDTH;

    m_asciiDataView = [[PPDataViewASCIIColumn alloc]
        initWithFrame:NSMakeRect(x, y, ASCII_DATA_VIEW_WIDTH, height)];
    [m_asciiDataView setDataSource:m_dataSource];
    [m_asciiDataView setAutoresizingMask:NSViewHeightSizable];
    [self addSubview:m_asciiDataView];
}

- (void)drawRect:(NSRect)rect
{
}

- (void)setDataSource:(id<PPDataViewDataSource>)dataSource
{
    [m_offsetColumnView setDataSource:dataSource];
    [m_hexDataView setDataSource:dataSource];
    [m_asciiDataView setDataSource:dataSource];
    [super setDataSource:dataSource];
}

- (void)setOffsetColumnTextColor:(NSColor*)color
{
    [m_offsetColumnView setTextColor:color];
}

- (void)setHexColumnTextColor:(NSColor*)color
{
    [m_hexDataView setTextColor:color];
}

- (void)setASCIIColumnTextColor:(NSColor*)color
{
    [m_asciiDataView setTextColor:color];
}

- (NSColor*)offsetColumntextColor
{
    return [m_offsetColumnView textColor];
}

- (NSColor*)hexColumntextColor
{
    return [m_hexDataView textColor];
}

- (NSColor*)ASCIIColumntextColor
{
    return [m_asciiDataView textColor];
}

- (void)setOffsetColumnVisible:(BOOL)flag
{
}

- (void)setShowHexColumnVisible:(BOOL)flag
{
}

- (void)setShowASCIIColumnVisible:(BOOL)flag
{
}

- (BOOL)offsetColumnVisible
{
    return YES;
}

- (BOOL)hexColumnVisible
{
    return YES;
}

- (BOOL)asciiColumnVisible
{
    return YES;
}

- (void)setFont:(NSFont*)font
{
    [m_offsetColumnView setFont:font];
    [m_hexDataView setFont:font];
    [m_asciiDataView setFont:font];
}

@end

/*
 * Abstract base
 */

@implementation PPDataViewAbstractBase

- (id)initWithFrame:(NSRect)frame
{
    if ((self = [super initWithFrame:frame]) != nil)
    {
        m_dataSource = nil;
        m_font = [[NSFont userFixedPitchFontOfSize:0.0f] retain];
        m_textColor = [[NSColor blackColor] retain];
    }
    return self;
}

- (BOOL)isFlipped
{
    return YES;
}

- (void)setDataSource:(id<PPDataViewDataSource>)dataSource;
{
    /* do not retain the data source, to avoid retain cycles */
    m_dataSource = dataSource;
    [self reloadDataSource];
}

- (id<PPDataViewDataSource>)dataSource
{
    return m_dataSource;
}

- (void)reloadDataSource
{
    NSLog(@"*** %@: implement -reloadDataSource! ***", self);
}

- (void)setFont:(NSFont*)font
{
    [font retain];
    [m_font release];
    m_font = font;
}

- (NSFont*)font
{
    return m_font;
}

- (void)setTextColor:(NSColor*)color
{
    [color retain];
    [m_textColor release];
    m_textColor = color;
}

- (NSColor*)textColor
{
    return m_textColor;
}

- (void)dealloc
{
    [m_font release];
    [m_textColor release];
    [super dealloc];
}

@end

/*
 * PPDataViewOffsetColumn
 */

@implementation PPDataViewOffsetColumn

- (id)initWithFrame:(NSRect)frame
{
    if ((self = [super initWithFrame:frame]) != nil)
    {
    }
    return self;
}

- (void)drawRect:(NSRect)rect
{
    [[NSColor redColor] set];
    NSRectFill(rect);
}

@end

/*
 * PPDataViewHexColumn
 */

@implementation PPDataViewHexColumn

- (id)initWithFrame:(NSRect)frame
{
    if ((self = [super initWithFrame:frame]) != nil)
    {
    }
    return self;
}

- (void)drawRect:(NSRect)rect
{
    [[NSColor greenColor] set];
    NSRectFill(rect);
}

@end

/*
 * PPDataViewASCIIColumn
 */

@implementation PPDataViewASCIIColumn

- (id)initWithFrame:(NSRect)frame
{
    if ((self = [super initWithFrame:frame]) != nil)
    {
    }
    return self;
}

- (void)drawRect:(NSRect)rect
{
    [[NSColor blueColor] set];
    NSRectFill(rect);
}

@end
