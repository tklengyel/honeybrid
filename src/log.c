/*
 * This file is part of the honeybrid project.
 *
 * Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <julien@linuxwall.info> for the University of Maryland)
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
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include <time.h>
#include <sys/time.h>
#include <err.h>

#include "tables.h"
#include "log.h"

/*!
 \def last_rotation
 \brief last timestamp the log file was rotated
 */
unsigned long last_rotation;

/*! 
 \Def file descriptor to log connections
 */

static FILE *logfd;

/*! log_header
 *
 *\brief return a header for debug log messages, including
 * the timestamp and the name of the function
 */
char* 
log_header(const char* function_name, int id)
{
	static char header[200];
	sprintf(header, "%s;%6u;%s:\t", now(), id, function_name);
	return header;
}

/*! now
 *
 *\brief return the current timestamp as a string
 */
char*
now(void)
{
	static char now[30];
	struct tm *tm;
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);
	tm=localtime(&tv.tv_sec);
	if (tm == NULL) {
		perror("localtime");
		return '\0';
	}
	sprintf(now,"%d-%02d-%02d %02d:%02d:%02d.%.6d", (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)tv.tv_usec);
	return now;
}

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
	if(level > LOG_LEVEL) {
		if(ddata != NULL)
			free(ddata);
	} else 	{
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
		sprintf(event->curtime,"%d-%02d-%02d %02d:%02d:%02d.%.6d", (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)tv.tv_usec);

		if(event->sdata != NULL && event->ddata == NULL) {
			g_print("%s;id:%5u;%s",event->curtime, event->id, event->sdata);
		} else if(event->sdata == NULL && event->ddata != NULL) {
			g_print("%s;id:%5u;%s",event->curtime, event->id, event->ddata);
			g_free(event->ddata);
		} else {
			g_print("%s;id:%5u;honeylog(): Incorrect event!!\n", event->curtime, event->id);
		}
		g_free(event->curtime);
		g_free(event);
	}
	return OK;
}

int
open_debug_log(void)
{
	int fd;
	if (0 != chdir(g_hash_table_lookup(config,"log_directory"))) 
                errx(1,"%s: can't change directory",__func__);
	if (NULL == g_hash_table_lookup(config,"debug_file")) 
                errx(1,"%s: no log file specified in the config",__func__);
	if ((fd = open( g_hash_table_lookup(config,"debug_file"), O_CREAT | O_WRONLY | O_APPEND, 0744)) == -1)
		err(1,"%s: open", __func__);
	if (0 != chdir(g_hash_table_lookup(config,"exec_directory"))) 
		warnx("%s: can't change directory",__func__);
	return fd;
}

int 
close_connection_log(void)
{
	return fclose(logfd);
}


/*! open log file
 \brief open the file honeybrid.log
 */
void 
open_connection_log(void)
{
	if (0 != chdir(g_hash_table_lookup(config,"log_directory"))) {
                errx(1,"%s: can't change directory",__func__);
        }

	if (NULL == g_hash_table_lookup(config,"log_file")) {
                errx(1,"%s: no log file specified in the config",__func__);
        }
	if (NULL == (logfd = fopen(g_hash_table_lookup(config,"log_file"),(char *) "a"))) {
		err(1,"fopen");
	} 

	/*! Enable line buffer */
	setlinebuf(logfd);

	if (0 != chdir(g_hash_table_lookup(config,"exec_directory"))) {
		warnx("%s: can't change directory",__func__);
        }
}

/*! rotate_connection_log
 *\brief rotate the file honeybrid.log every hour
 */
//void rotate_connection_log(int signal_nb, void *siginfo, void *context)
void rotate_connection_log(int signal_nb)
{
	L("rotate_connection_log()\tCalled\n", NULL, LOG_ALL, LOG_LOG);

	unsigned long timestamp;
	//char *logfile_name;
	//char *new_name;
	GString *logfile_name;
	GString *new_name;
	char *logbuf;

	struct tm *tm;
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
        tm=localtime(&tv.tv_sec);
        if (tm == NULL) {
               perror("localtime");
               return;
        }

	timestamp = 	( (tm->tm_year)*(1000000)
			+ (1+tm->tm_mon)*(10000)
			+ (tm->tm_mday)*(100)
			+ (tm->tm_hour) );

	if (last_rotation == 0)
	{
		last_rotation = timestamp;

		logbuf = malloc(256);
		sprintf(logbuf,"rotate_connection_log()\tlast_rotation initialized to %lu\n", last_rotation);
		L(NULL, logbuf, 4, LOG_LOG);

		return;
	}

	if (timestamp > last_rotation || signal_nb > 0)
	{
		if (signal_nb > 0) {
			L("rotate_connection_log()\tSIGUSR1 received, rotating log...\n", NULL, LOG_MED, LOG_LOG);
		} else {
			L("rotate_connection_log()\tTime to rotate the log...\n", NULL, LOG_MED, LOG_LOG);
		}

		fclose(logfd);

		//logfile_name = malloc(sizeof(g_hash_table_lookup(config,"log_file"))+1);
		//logfile_name = malloc(512);
		///logfile_name = g_new0(char, 256);
		///logfile_name = g_hash_table_lookup(config,"log_file");
		///new_name = malloc(sizeof(logfile_name) + 64);
	        ///sprintf(new_name,"%s.%d%02d%02d_%02d%02d", logfile_name, (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min);
		logfile_name = g_string_new( g_hash_table_lookup(config,"log_file") );
		#ifdef DEBUG
		g_print("rotate_connection_log()\tlogfile_name is %s\n", logfile_name->str);
		#endif

		new_name = g_string_new("");
		g_string_printf( new_name, "%s.%d%02d%02d_%02d%02d", logfile_name->str, (1900+tm->tm_year), (1+tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min);

		logbuf = malloc(512);
		sprintf(logbuf, "rotate_connection_log()\tRotating log file from %s to %s\n", logfile_name->str, new_name->str);
		L(NULL, logbuf, LOG_HIGH, LOG_LOG);

		chdir(g_hash_table_lookup(config,"log_directory"));
		
		if (rename(logfile_name->str, new_name->str)) {
			L("rotate_connection_log()\tERROR: can't rename log file!\n", NULL, LOG_MED, LOG_LOG);
		}

		//i = open(logfile_name, O_RDWR | O_CREAT, 0640);
		logfd = fopen(g_hash_table_lookup(config,"log_file"), (char *)"a");

		chdir(g_hash_table_lookup(config,"exec_directory"));

		///g_free(logfile_name);
		///free(new_name);
		g_string_free(logfile_name, TRUE);
		g_string_free(new_name, TRUE);

		/*! The last step is to update last_rotation
		 */
		last_rotation = timestamp;

		logbuf = malloc(256);
		sprintf(logbuf,"rotate_connection_log()\tLog file re-opened. last_rotation updated to %lu\n", last_rotation);
		L(NULL, logbuf, LOG_HIGH, LOG_LOG);


	}

	return;
}

/*! connection_stat
 *\brief compile a single line of final statistics for every connection handled by honeybrid:
 * Basic flow information: start timestamp, source IP, source Port, destination IP, destination Port, protocol, cumulative flags if TCP
 * INVALID information: duration, reason, packet, byte
 * INIT information: duration, packet, byte
 * DECIDE information: duration, rule, packet id, high interaction ip and port
 * REPLAY information: duration, problem, packet, byte
 * FORWARD information: duration, packet, byte
 */

void connection_log(struct conn_struct *conn)
{

	/*! if log rotation is configured, then we call rotate_connection_log()
	 */
	if ( NULL != strstr(g_hash_table_lookup(config,"log_rotation"),"1") ) {
		rotate_connection_log(0);
	}

	gchar **tuple;
	tuple = g_strsplit( conn->key, ":", 0);

	GString *proto  = g_string_new("");
	switch( conn->protocol ) {
		case 6:
			g_string_printf(proto,"TCP");
			break;
		case 17:
			g_string_printf(proto,"UDP");
			break;
		default:
			g_string_printf(proto,"%d",conn->protocol);
			break;
	}

	GString *status = g_string_new("");
	switch( conn->state ) {
		case INIT:
			g_string_printf(status,"INIT");
			break;
		case DECISION:
			g_string_printf(status,"DECISION");
			break;
		case REPLAY:
			g_string_printf(status,"REPLAY");
			break;
		case FORWARD:
			g_string_printf(status,"FORWARD");
			break;
		case PROXY:
			g_string_printf(status,"PROXY");
			break;
		case DROP:
			g_string_printf(status,"DROP");
			break;
		case CONTROL:
			g_string_printf(status,"CONTROL");
			break;
		default:
			g_string_printf(status,"INVALID");
	}

	gint i;
	GString *status_info[6];
	gdouble lasttime = conn->start_microtime;
	gdouble duration = 0.0;
	for( i = INIT; i<=PROXY; i++) {
		status_info[i] = g_string_new("");
		if ( i <= conn->state ) {
			if (conn->stat_time[i] > 0) {
				duration = (conn->stat_time[i] - lasttime);
				lasttime = conn->stat_time[i];
			} else {
				duration = 0.0;
			}
			if ( i == REPLAY && conn->replay_problem > 0 ) {
				g_string_printf( status_info[i], "%.3f|%d|%d|error:%d", duration, conn->stat_packet[i], conn->stat_byte[i], conn->replay_problem);
			} else if ( i == DECISION ) {
				g_string_printf( status_info[i], "%.3f|%s", duration, conn->decision_rule->str);
			} else {
				g_string_printf( status_info[i], "%.3f|%d|%d", duration, conn->stat_packet[i], conn->stat_byte[i]);
			}
		} else {
			if ( i == REPLAY )
				g_string_printf( status_info[i], ".|.|.|.");
			else if ( i == DECISION )
				g_string_printf( status_info[i], ".|.");
			else
				g_string_printf( status_info[i], ".|.|.");
		}
	}

	gdouble total_duration = (lasttime - conn->start_microtime);

	/*
	GString *decision_info = g_string_new(".");
	if (conn->state >= DECISION) {
		g_string_printf(decision_info, "%d:%s", conn->decision_packet_id, conn->decision_rule->str);
	}
	*/
	
	char *logbuf = malloc(1024);	//1024 might be too short!

	/*! Output according to the format configured */
	if ( NULL != g_hash_table_lookup(config,"log_format") && NULL != strstr(g_hash_table_lookup(config,"log_format"),"csv") ) {
		sprintf(logbuf,"%s,%.3f,%s,%s,%s,%s,%s,%d,%d,%s,%d,%s,%s,%s,%s,%s\n", conn->start_timestamp->str, total_duration, proto->str, tuple[0], tuple[1], tuple[2], tuple[3], conn->total_packet, conn->total_byte, status->str, conn->id, 
		//status_info[INVALID]->str,
		status_info[INIT]->str,
		status_info[DECISION]->str,
		status_info[REPLAY]->str,
		status_info[FORWARD]->str,
		status_info[PROXY]->str
		);
        } else {
		sprintf(logbuf,"%s %.3f %s %s:%s -> %s:%s %d %d %s ** %d %s %s %s %s %s\n", conn->start_timestamp->str, total_duration, proto->str, tuple[0], tuple[1], tuple[2], tuple[3], conn->total_packet, conn->total_byte, status->str, conn->id, 
		//status_info[INVALID]->str,
		status_info[INIT]->str,
		status_info[DECISION]->str,
		status_info[REPLAY]->str,
		status_info[FORWARD]->str,
		status_info[PROXY]->str
		);
	}	
	///g_printerr("%s",logbuf);	
	fprintf(logfd, "%s", logbuf);
	
	g_free(logbuf);
	g_strfreev(tuple);	/// ROBIN - 20090326-1007 according to valgrind output
	//g_free(status_info);	/// seg fault
        //L(NULL,logbuf,1,conn->id);
}
