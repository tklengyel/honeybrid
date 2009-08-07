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
#********************************************************************************#

## main configuration:
config {
	## output mode
	# 1 = syslog
	# 2 = stdout (do not daemonize)
	# 3 = log files
        output = 3;

	## 'yes' to send reset to external source, 'no' to remain silent
        reset_ext = yes;

	## pid directory
        exec_directory = $RUNDIR;

	## log file directory
        log_directory = $LOGDIR;

	## enable automatic hourly log rotation (only for connection logs, not for debug logs)
        log_rotation = 0;

	## connection log file (log_directory defines the path)
        log_file = $LOGFILE;

	## debug log file (detailed internal process, log_directory defines the path)
        debug_file = $DEBUGFILE;

	## Number of seconds after which network sessions are expired
        expiration_delay = 120;
}


## module configuration:
module \"hash\" {
        function = hash;
        backup = /etc/honeybrid/hash.tb;
}

module \"counter\" {
        function = counter;
        counter = 2;
}

module \"control\" {
        function = control;
	backup = /etc/honeybrid/control.tb;
	expiration = 600;
	max_packet = 1000;
}


## target configuration:
target {
        filter \"dst host 192.168.0.10 and port 80\";
        frontend 192.168.0.10 \"hash\";
        backend 192.168.0.11 \"hash\";
	control \"control\";
}
" >$CONF
