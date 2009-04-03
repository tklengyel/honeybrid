#!/bin/sh
#
# This file is part of the honeybrid project.
# 
# Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
# (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <jvehent@umd.edu> for the University of Maryland)
# 
# Honeybrid is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

echo "#********************************************************************************#
#*			HONEYBRID CONFIGURATION FILE				*#
#*										*#
#* syntax is : key = 'value' (be careful, the pattern ' = ' is important)	*#
#* comments lines starts with #							*#
#********************************************************************************#

## output mode
#
# 1 = syslog
# 2 = stdout (do not daemonize)
# 3 = log files
#

output = 3


## verbose level
#
# 1 errors only
# 2 minimal redirection information
# 3 full redirection information
# 4 internal processing events
# 5 permanent internal processing events
#

log_level = 4


## send reset to external source...
#

reset_ext = yes


## pid directory
#

exec_directory = $RUNDIR


## log directory
#

log_directory = $LOGDIR

## log file for connections
#

log_file = $LOGFILE

## log file hourly rotation
#  sending the signal USR1 to Honeybrid will force the logs to rotate
#

log_rotation = 1

## log format
#  if you need connections to be logged in csv format, just uncomment the following line
#

#log_format = csv

## debug file for internal process
#  (this one is never rotated)
#

debug_file = $DEBUGFILE


## static redirect table
#

redirect_table = $CONFDIR/$RULE


## delay in second to expire connections
#

expiration_delay = 120

## enable pcap recording
#

record = 1


## dump file path and prefix
# (a time value and a .pcap suffix will be automatically
# added by the program)
#

conn_record = $LOGDIR/honeybrid_pcap_

## Source Module table file
#

sourcetable = $CONFDIR/source.tb

## SHA1 Module table file
#

sha1table = $CONFDIR/sha1_bdd.tb">$CONF
