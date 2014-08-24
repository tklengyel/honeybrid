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

#ifndef MANAGEMENT_H_
#define MANAGEMENT_H_

#include "types.h"
#include "structs.h"
#include "connections.h"
#include "decision_engine.h"

status_t add_target(struct target *target);
status_t remove_target(int64_t targetID);

status_t add_back_handler(struct target *target, struct handler *handler);
status_t remove_back_handler(struct target *target, int64_t backendID);

status_t add_intra_handler(struct target *target, struct addr *target_ip,
		struct handler *handler);
status_t remove_intra_handler(struct target *target, int64_t intraID);


#endif /* MANAGEMENT_H_ */
