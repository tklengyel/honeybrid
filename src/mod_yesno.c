/*
 * This file is part of the honeybrid project.
 *
 * 2007-2009 University of Maryland (http://www.umd.edu)
 * Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu>
 * and Julien Vehent <julien@linuxwall.info>
 *
 * 2012-2014 University of Connecticut (http://www.uconn.edu)
 * Tamas K Lengyel <tamas.k.lengyel@gmail.com>
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

/*! \file yesno_mod.c
 * \brief Yesno Module for honeybrid Decision Engine
 *
 * This module always decides to redirect or not according to the "yes" (1) or "no" (0) value of its argument
 *
 \author Thomas Coquelin, 2008
 */

#include <string.h>

#include "modules.h"

/*! mod_yesno requires the configuration of the following mandatory parameter:
 - "value", if 0 it rejects everything, if 1 it accepts everything
 */

/*! mod_yesno
 \param[in] args, struct that contain the node and the datas to process
 *
 \param[out] set result to 1 when 'arg' is "yes", 0 otherwise
 */
mod_result_t mod_yesno(struct mod_args *args) {
    printdbg("%s Module called\n", H(args->pkt->conn->id));

    int *param;

    if ((param = (int *) g_hash_table_lookup(args->node->config, "value"))
            == NULL) {
        /*! We can't decide */
        printdbg("%s mandatory argument 'value' undefined!\n",
                H(args->pkt->conn->id));
        return DEFER;
    }

    if (0 == *param) {
        /*! We accept this packet */
        printdbg("%s PACKET MATCH RULE for yesno(%d)\n", H(args->pkt->conn->id),
                *param);
        return ACCEPT;
    } else {
        /*! We reject this packet */
        printdbg("%s PACKET DOES NOT MATCH RULE for yesno(%d)\n",
                H(args->pkt->conn->id), *param);
        return REJECT;
    }
}

