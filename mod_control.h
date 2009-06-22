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

/*! \file mod_control.h
 * \brief header for control engine 
 *
 \author Robin Berthier, 2009
 */

/*!
 \def control_info
 \brief Structure that carries meta information about IP addresses stored by the control engine
 */

struct control_info
{
	gint counter;
	gint first_seen;	
	gint last_seen;	
};

/*!
 \def control bdd hash table
 */
GHashTable *control_bdd;

int expire_control (gpointer key, gpointer value, gint *now);
void print_control_info (gpointer key, gpointer value, FILE *fd);
void control_print();
int init_control();
int control(struct pkt_struct *pkt);

