/**
 * SPDX-FileCopyrightText: Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * 
 * Private but exported symbols from trace-cmd/lib/trace-cmd/include/private/trace-cmd-private.h
 */

#ifndef _TRACE_CMD_PRIVATE_H
#define _TRACE_CMD_PRIVATE_H

struct tracecmd_input;

const char *tracecmd_get_uname(struct tracecmd_input *handle);

#endif
