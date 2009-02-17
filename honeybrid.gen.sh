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

#################################################################
# 			honeybrid.sh				#
#################################################################

echo "#!/bin/sh

### BEGIN INIT INFO
# Provides: $BIN
### END INIT INFO

BIN=$BINDIR/$BIN
CONFIG=$CONFDIR/$CONF
LOGDIR=$LOGDIR
RUNDIR=$RUNDIR
LOGFILE=\`echo \$LOGDIR\"/$BIN.log\"\`
PID=\`echo \$RUNDIR\"/honeybrid.pid\"\`

# /etc/init.d/$BIN: start and stop the daemon

test -x \$BIN || exit 0

case \"\$1\" in
  start)

# test conf file
        if test -f \$CONFIG
        then
		echo \"\$CONFIG found\"
        else
                echo \"\$CONFIG is missing... can't start\"
                exit -1
        fi

# backup log file if exists
        if test -f \$LOGFILE
        then
                DATE=\`date +%Y%m%d_%H%M\`
                BACKUP=\`echo \"\$LOGFILE\".\"\$DATE\"\`
                mv \$LOGFILE \$BACKUP
		echo \"\$LOGFILE backed up to \$BACKUP\"
        fi


        if start-stop-daemon --start --quiet --oknodo --pidfile \$PID --exec \$BIN -- -c \$CONFIG; then
            exit 0
        else
            exit 1
        fi
        ;;
  stop)
        echo \"Stopping \$BIN\" 
        if start-stop-daemon --stop --quiet --oknodo --pidfile \$PID --exec \$BIN -- -x \`cat \$PID\`; then
                #echo \"killing TCPDUMP recording\"
                #kill -9 \`ps -edf | grep tcpdump |awk {'print \$2'}\`
                if test -f \$PID; then
                        rm \$PID
                fi
                exit 0
        else
            exit 1
        fi
        ;;

  add)
	echo \"Adding an IP to the routing and queueing tables\"
	if [ \$# -gt 1 ];
        then
                LIH_IP=\$2
        else
                echo \"Please provide the IP address of LIH: \"
                read LIH_IP
        fi
	if [ \$# -gt 2 ];
        then
                LIH_MAC=\$3
        else
                echo \"Please provide the MAC address of LIH: \"
                read LIH_MAC
        fi
	if [ \$# -gt 3 ];
        then
                HIH_IP=\$4
        else
                echo \"Please provide the IP address of HIH: \"
                read HIH_IP
        fi
	if [ \$# -gt 4 ];
        then
                EXT_IF=\$5
        else
                echo \"Please provide the name of the external network interface: \"
                read EXT_IF
        fi
	if [ \$# -gt 5 ];
        then
                INT_IF=\$6
        else
                echo \"Please provide the name of the internal network interface: \"
                read INT_IF
        fi

	#echo \"LIH_IP is: \$LIH_IP\"
	#echo \"LIH_MAC is: \$LIH_MAC\"
	#echo \"HIH_IP is: \$HIH_IP\"
	#echo \"EXT_IF is: \$EXT_IF\"
	#echo \"INT_IF is: \$INT_IF\"

	echo \"Proceeding...\"

	route add -host \$LIH_IP \$INT_IF
	arp -i \$EXT_IF -Ds \$LIH_IP \$EXT_IF pub
	arp -s \$LIH_IP \$LIH_MAC
	iptables -I FORWARD -i \$EXT_IF ! -p icmp -d \$LIH_IP -j QUEUE -m comment --comment \"honeybrid\"
        iptables -I FORWARD -i \$INT_IF ! -p icmp -s \$LIH_IP -j QUEUE -m comment --comment \"honeybrid\"
        iptables -I FORWARD -p icmp -s \$LIH_IP -j ACCEPT -m comment --comment \"honeybrid\"
        iptables -I FORWARD -p icmp -d \$LIH_IP -j ACCEPT -m comment --comment \"honeybrid\"
	iptables -I FORWARD -i \$INT_IF ! -p icmp -s \$HIH_IP -j QUEUE -m comment --comment \"honeybrid\"
	iptables -I FORWARD -i \$INT_IF ! -p icmp -d \$HIH_IP -j QUEUE -m comment --comment \"honeybrid\"

	echo \"done.\"
        exit 0
	;;
  del)
	echo \"Removing an IP from the routing and queueing tables\"
	if [ \$# -gt 1 ];
        then
                LIH_IP=\$2
        else
                echo \"Please provide the IP address of LIH: \"
                read LIH_IP
        fi
	if [ \$# -gt 2 ];
        then
                HIH_IP=\$3
        else
                echo \"Please provide the IP address of HIH: \"
                read HIH_IP
        fi
	if [ \$# -gt 3 ];
        then
                EXT_IF=\$4
        else
                echo \"Please provide the name of the external network interface: \"
                read EXT_IF
        fi
	if [ \$# -gt 4 ];
        then
                INT_IF=\$5
        else
                echo \"Please provide the name of the internal network interface: \"
                read INT_IF
        fi

	echo \"Proceeding...\"

	route del -host \$LIH_IP \$INT_IF
	arp -i \$EXT_IF -d \$LIH_IP
	iptables -D FORWARD -i \$EXT_IF ! -p icmp -d \$LIH_IP -j QUEUE
        iptables -D FORWARD -i \$INT_IF ! -p icmp -s \$LIH_IP -j QUEUE
        iptables -D FORWARD -p icmp -s \$LIH_IP -j ACCEPT
        iptables -D FORWARD -p icmp -d \$LIH_IP -j ACCEPT
	iptables -D FORWARD -i \$INT_IF ! -p icmp -s \$HIH_IP -j QUEUE
	iptables -D FORWARD -i \$INT_IF ! -p icmp -d \$HIH_IP -j QUEUE

	echo \"done.\"
        exit 0
	;;

  *)
        echo \"Usage: /etc/init.d/$BIN {start|stop|add <lih_ip> <lih_mac> <hih_ip> <ext_if> <int_if>|del <lih_ip> <hih_ip> <ext_if> <int_if>}\"
	
        exit 1
esac

exit 0
" >$BIN.sh
