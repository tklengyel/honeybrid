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

/*! \file sha1_mod.h
 * \brief header for Source Module for honeybrid Decision Engine
 *
 \author Robin Berthier, 2009
 */

/*!
 \def sha1_info
 \brief Structure that carries meta information about sha1 signatures
 */

struct hash_info
{
	gint bdd_id;
	gint id;
	gint counter;
	gint port;
	gint packet;
	gint byte;
	gint first_seen;	
	gint duration;	
	gchar *ascii;
};
