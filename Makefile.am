# Copyright (C) 2009 Robin Berthier <robinb@umd.edu>
#  
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without 
# modifications, as long as this notice is preserved.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

EXTRA_DIST = reconf configure honeybrid.conf honeybrid.sh
SUBDIRS = m4 src @doc@

install-data-am:
	@echo
	@echo "========================================="
	@echo "     Thanks for using honeybrid!"
	@echo 
	@echo "The honeybrid binary was installed in"
	@echo " /usr/local/sbin/"
	@echo
	@echo "To complete the installation on Linux,"
	@echo "you can type the following commands:"
	@echo " sudo mkdir /etc/honeybrid"
	@echo " sudo cp ./honeybrid.conf /etc/honeybrid/"
	@echo " sudo mkdir /var/log/honeybrid"
	@echo " sudo cp ./honeybrid.sh /etc/init.d/"
	@echo
	@echo "Do not forget to edit honeybrid.conf"
	@echo "before running:"
	@echo " sudo /etc/init.d/honeybrid.sh start"
	@echo 
	@echo "Please submit bugs and suggestions on"
	@echo "honeybrid.sf.net or to robinb@umd.edu"	
	@echo "========================================="
	@echo

