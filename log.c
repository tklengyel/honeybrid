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

/*! \file log.c
    \brief Log function for honeybrid

    \author Julien Vehent, 2007
    \author Thomas Coquelin, 2008
 */

#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "tables.h"
#include "log.h"


/*! honeylog
 *
 \brief add a log entry in the singly linked list
 *
 \param[in] static string pointer
 \param[in] dynamicaly allocated string pointer
 \param[in] log level of event
 \param[in] connection id
 *
 \return OK when done, NOK on failure
 */
int honeylog(char *sdata, char *ddata, int level, unsigned id)
{
	/*!filter events upon their log level*/
	char* log_level = g_hash_table_lookup(config,"log_level");
	if(log_level == NULL)
		log_level = "3";
	if(level> atoi(log_level))
	{
		if(ddata != NULL)
			free(ddata);
	}
	else
	{
		struct tm *tm;
		struct timeval tv;
		struct timezone tz;
		struct log_event *event = malloc(sizeof(struct log_event));
		gettimeofday(&tv, &tz);
		tm=localtime(&tv.tv_sec);
		if (tm == NULL) {
			perror("localtime");
			return NOK;
		}
		event->sdata = sdata;
		event->ddata = ddata;
		event->level = level;
		event->id = id;
		event->curtime = malloc(30);
		//strftime(event->curtime, sizeof(curtime), "%F %T", tm);
		sprintf(event->curtime,"%d-%02d-%02d %02d:%02d:%02d.%.6d", (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)tv.tv_usec);

	/*! store the address of the payload as a new entry of the list
	 *
	 * (set up a lock to protect the writing)
	 */
		g_static_rw_lock_writer_lock (&loglock);

		log_list = g_slist_append(log_list, event);

		g_static_rw_lock_writer_unlock (&loglock);
	}
	return OK;
}

/*! write_log
 *
 \brief wake up every 10s from a thread, check the singly linked list and write the new entries to syslog
 *
 */
void write_log()
{
	struct log_event *event;
	/*! infinite loop that check new entries in the list and write them
	 */
	while(1){
	g_usleep(10000);
	/*! check for new log events every 10 ms
	 */
	while ( g_slist_length(log_list) > 0 )
	{
		/*! get the value */
		/*! process it
		 *
		 * log pattern is :
		 * <timestamp>;<id>;<log string>;
		 */
		event = g_slist_nth_data (log_list, 0);
		if(event->sdata != NULL && event->ddata == NULL)
		{
			if ( NULL != strstr(g_hash_table_lookup(config,"output"),"1") )
				/*! log to syslog */
				syslog(LOG_INFO | LOG_USER, "%s id:%5u %s",event->curtime, event->id, event->sdata);
			else
				/*! or log to stdout */
				g_print("%s;id:%5u;%s",event->curtime, event->id, event->sdata);
		}
		else if(event->sdata == NULL && event->ddata != NULL)
		{
			if ( NULL != strstr(g_hash_table_lookup(config,"output"),"1") )
				/*! log to syslog */
				syslog(LOG_INFO | LOG_USER, "%s id:%5u %s",event->curtime, event->id, event->ddata);
			else
				/*! or log to stdout */
				g_print("%s;id:%5u;%s",event->curtime, event->id, event->ddata);
			free(event->ddata);
		}
		else
			g_print("write_log(): Incorrect event\n");
		/*! free the memory */
		free(event->curtime);
		g_static_rw_lock_writer_lock (&loglock);
		log_list = g_slist_delete_link(log_list, log_list);
		g_static_rw_lock_writer_unlock (&loglock);
		free(event);
	}
	}
}

