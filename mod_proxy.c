/*
 * This file is part of the honeybrid project.
 *
 * Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <jvehent@umd.edu> for the University of Maryland)
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

/*! \file mod_proxy.c
 * \brief Packet counter Module for honeybrid Decision Engine
 *
 * This module returns the position of a packet in the connection
 *
 *
 \author Julien Vehent, 2007
 \author Thomas Coquelin, 2008
 */

#include <stdlib.h>

#include "modules.h"
#include "tables.h"
#include "mod_proxy.h"

/*! mod_proxy
 \param[in] args, struct that contain the node and the datas to process
 *
 \param[out] set result to 1 packet position match arg, 0 otherwise
 */
void mod_proxy(struct mod_args args)
{
	char *logbuf;
	L("mod_proxy():\tModule called\n", NULL, 3,args.pkt->conn->id);
	int pktval = atoi(args.node->arg);

	if(pktval <= args.pkt->conn->count_data_pkt_from_intruder)
	{
		/*! we introduce a new return value, meaning that we can skip the replay part and go
		    directly in PROXY mode, which is like FORWARD but without NATing */
		//args.node->result = 1; 	/* This one would go to the replay process */
		args.node->result = 2;		/* This one goes directly to the proxy mode */
		logbuf = malloc(128);
		sprintf(logbuf,"mod_proxy():\tPACKET MATCH RULE for proxy(%d)\n", pktval);
		L(NULL, logbuf, 2, args.pkt->conn->id);
	}
	else
	{
		args.node->result = 0;
		logbuf = malloc(128);
                sprintf(logbuf,"mod_proxy():\tPACKET DOES NOT MATCH RULE for proxy(%d)\n", pktval);
                L(NULL, logbuf, 2, args.pkt->conn->id);
	}
}

