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

#ifndef _PACKETPEEPER_H_
#define _PACKETPEEPER_H_

#include <math.h>

#define ARRAY_NELEMS(x) (sizeof(x) / sizeof((x)[0]))
#define TIMEVAL_TO_NSDATE(timeval)                                        \
    ([[[NSDate alloc]                                                     \
        initWithTimeIntervalSinceReferenceDate:(((timeval).tv_sec +       \
                                                 fabs(                    \
                                                     (timeval).tv_usec /  \
                                                     1000000.0)) -        \
                                                NSTimeIntervalSince1970)] \
        autorelease])

#define PP_VERSION_NUMBER 1.3f

/* user defaults key */
#define PPCAPTUREFILTERMANAGER_SAVED_FILTERS \
    @"PPCaptureFilterManager.SavedFilters"
#define PP_PREFS_VERSION_NUMBER_KEY @"PPReleaseNumber"
#define PPSTREAMSWINDOW_PACKETTABLEVIEW_COLUMNS_KEY \
    @"PPStreamsWindow.PacketTableView.Columns"
#define PPSTREAMSWINDOW_STREAMTABLEVIEW_COLUMNS_KEY \
    @"PPStreamsWindow.StreamTableView.Columns"
#define PPDOCUMENT_TABLEVIEW_COLUMNS_KEY @"PPDocument.TableView.Columns"
#define CAPTURE_SETUP_INTERFACE          @"PPCaptureSetup.Interface"
#define CAPTURE_SETUP_PROMISC            @"PPCaptureSetup.Promisc"
#define CAPTURE_SETUP_REALTIME           @"PPCaptureSetup.RealTime"
#define CAPTURE_SETUP_BUFSIZE            @"PPCaptureSetup.BufSize"
#define CAPTURE_SETUP_UPDATE_FREQUENCY   @"PPCaptureSetup.UpdateFreq"
#define PPDOCUMENT_AUTOSCROLLING         @"PPDocument.AutoScrolling"
#define PPDOCUMENT_DATA_INSPECTOR        @"PPDocument.DataInspector"
#define PPSTREAMSWINDOW_AUTOSCROLLING    @"PPStreamsWindow.AutoScrolling"
#define PPTCPSTREAMCONTROLLER_IP_DROP_BAD_CHECKSUMS \
    @"PPTCPStreamControllerIPDropBadChecksums"
#define PPTCPSTREAMCONTROLLER_TCP_DROP_BAD_CHECKSUMS \
    @"PPTCPStreamControllerTCPDropBadChecksums"
#define PPHEXVIEW_LINECOLUMN_MODE @"PPHexView.LineColumnMode"

/* how often to update progress bars, in seconds */
#define DEFAULT_PROGRESSBAR_UPDATE_FREQUENCY 0.3

/* how often to update the user interface, in seconds */
#define DEFAULT_UI_UPDATE_FREQUENCY 1.0f

#define OUTLINEVIEW_DATE_FORMAT @"EEEE, dd MMMM yyyy, HH:mm:ss.SSS"
#define TABLEVIEW_DATE_FORMAT   @"yyyy-MM-dd HH:mm:ss.SSS"

#define PPCAPTUREWINDOW_STOPMODE_ANY_TAG 1
#define PPCAPTUREWINDOW_STOPMODE_ALL_TAG 2

/* maximum number of chunks to reassemble before allowing the ui to update */
#define PPTCPSTREAMREASSEMBLER_REASSEMBLE_CHUNKS_MAX 5000

/* identifies used as menu item and table column item identifiers for
   the streams window streams table view */

#define PPSTREAMSWINDOW_STREAMS_TABLE_MENU_TAG 1
#define PPSTREAMSWINDOW_PACKETS_TABLE_MENU_TAG 2

#define PPSTREAMSWINDOW_STREAMS_TABLE_SRC_IP_ADDRESS @"SrcIP"
#define PPSTREAMSWINDOW_STREAMS_TABLE_DST_IP_ADDRESS @"DstIP"
#define PPSTREAMSWINDOW_STREAMS_TABLE_SRC_HOSTNAME   @"SrcHost"
#define PPSTREAMSWINDOW_STREAMS_TABLE_DST_HOSTNAME   @"DstHost"
#define PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORT       @"SrcPort"
#define PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORT       @"DstPort"
#define PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORTNAME   @"SrcPortName"
#define PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORTNAME   @"DstPortName"
#define PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_SENT     @"Sent"
#define PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_RECV     @"Recv"
#define PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_TOTAL    @"Total"
#define PPSTREAMSWINDOW_STREAMS_TABLE_STATUS         @"Status"

#define PPSTREAMSWINDOW_STREAMS_TABLE_SRC_IP_ADDRESS_TAG 1
#define PPSTREAMSWINDOW_STREAMS_TABLE_DST_IP_ADDRESS_TAG 2
#define PPSTREAMSWINDOW_STREAMS_TABLE_SRC_HOSTNAME_TAG   3
#define PPSTREAMSWINDOW_STREAMS_TABLE_DST_HOSTNAME_TAG   4
#define PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORT_TAG       5
#define PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORT_TAG       6
#define PPSTREAMSWINDOW_STREAMS_TABLE_SRC_PORTNAME_TAG   7
#define PPSTREAMSWINDOW_STREAMS_TABLE_DST_PORTNAME_TAG   8
#define PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_SENT_TAG     9
#define PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_RECV_TAG     10
#define PPSTREAMSWINDOW_STREAMS_TABLE_BYTES_TOTAL_TAG    11
#define PPSTREAMSWINDOW_STREAMS_TABLE_STATUS_TAG         12

/* tags used to (easily) traverse the app menu, set in MainMenu.nib */
#define APPMENU_ITEM_VIEW_TAG           1
#define APPMENU_ITEM_COLUMNS_TAG        2
#define APPMENU_ITEM_SORTBY_TAG         3
#define APPMENU_ITEM_SCROLLING_TAG      6
#define APPMENU_ITEM_DATA_INSPECTOR_TAG 7

#define GRAPH_UTILISATION_TAG 0
#define GRAPH_NODES_TAG       1
#define GRAPH_PROTOCOLS_TAG   2
#define GRAPH_SIZE_TAG        3

#define PP_DECODERS_COUNT 9

#endif /* _PACKETPEEPER_H_ */
