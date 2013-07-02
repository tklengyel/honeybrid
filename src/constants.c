/*
 * This file is part of the honeybrid project.
 *
 * 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <julien@linuxwall.info> for the University of Maryland)
 *
 * 2012-2013 University of Connecticut (http://www.uconn.edu)
 * (Extended by Tamas K Lengyel <tamas.k.lengyel@gmail.com>
 *
 * Honeybrid is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*!	\file constants.c
 \brief

 This file is intended to provide a place for the constants declared
 in Honeybrid to be placed at.

 */

#include "constants.h"

const char banner[] =
	"    __  __                       __         _     __\n"
	"   / / / /___  ____  ___  __  __/ /_  _____(_)___/ /\n"
	"  / /_/ / __ \\/ __ \\/ _ \\/ / / / __ \\/ ___/ / __  /\n"
	" / __  / /_/ / / / /  __/ /_/ / /_/ / /  / / /_/ /\n"
	"/_/ /_/\\____/_/ /_/\\___/\\__, /_.___/_/  /_/\\__,_/\n"
	"                       /____/";

const char unsupported_protocol[] = "Unsupported protocol";
const char unknown[] = "UNKNOWN";

const char* protocol_string[IPPROTO_MAX] = {

	[0 ... IPPROTO_MAX-1] = unsupported_protocol,

	[IPPROTO_TCP] 	= "TCP",
	[IPPROTO_UDP] 	= "UDP"
};

const char *role_string[__MAX_ROLE] = {

	[0 ... __MAX_ROLE-1] = unknown,

	[EXT]   = "[EXT] External",
	[INT]   = "[INT] Internal - Either LIH or HIH",
	[LIH]   = "[LIH] Low-interaction honeypot",
	[HIH]   = "[HIH] High-interaction honeypot",
	[INTRA] = "[INTRA] Internal target"
};

const char *conn_status_string[__MAX_CONN_STATUS] = {

	[0 ... __MAX_CONN_STATUS-1] = unknown,

	[INIT] 		= "INIT",
	[DECISION] 	= "DECISION",
	[REPLAY] 	= "REPLAY",
	[FORWARD] 	= "FORWARD",
	[PROXY] 	= "PROXY",
	[DROP] 		= "DROP",
	[CONTROL] 	= "CONTROL"
};

const char *mod_result_string[] = {
	[DEFER] = "DEFER",
	[ACCEPT] = "ACCEPT",
	[REJECT] = "REJECT"
};
