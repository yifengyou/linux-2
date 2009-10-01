/*
  drbd_config.h
  DRBD's compile time configuration.

  drbd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  drbd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with drbd; see the file COPYING.  If not, write to
  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef DRBD_CONFIG_H
#define DRBD_CONFIG_H

extern const char *drbd_buildtag(void);

#define REL_VERSION "8.3.1"
#define API_VERSION 88
#define PRO_VERSION_MIN 86
#define PRO_VERSION_MAX 90

#ifndef __CHECKER__   /* for a sparse run, we need all STATICs */
#define DBG_ALL_SYMBOLS /* no static functs, improves quality of OOPS traces */
#endif


/* Define this to enable dynamic tracing controlled by module parameters
 * at run time. This enables ALL use of dynamic tracing including packet
 * and bio dumping, etc */
#define ENABLE_DYNAMIC_TRACE

/* Enable fault insertion code */
#define DRBD_ENABLE_FAULTS

#endif
