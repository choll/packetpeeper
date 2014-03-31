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

#ifndef PPPYDECODERPLUGIN_H_
#define PPPYDECODERPLUGIN_H_

#include "PPDecoderPlugin.h"

@class OutlineViewItem;

@interface PPPyDecoderPlugin : NSObject <PPDecoderPlugin>
{
	PyObject *module;
	PyObject *canDecodeProtocolFunc;
	PyObject *shortNameFunc;
	PyObject *longNameFunc;
	PyObject *infoFunc;
	PyObject *descriptionTreeFunc;
	PyObject *isValidDataFunc;
	PyObject *columnIdentifiersFunc;
	PyObject *columnStringForIndexFunc;
	PyObject *compareColumnForIndex;
}

- (void)clear; /* private method */

@end

#endif
