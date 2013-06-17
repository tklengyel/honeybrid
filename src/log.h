/*
 * This file is part of the honeybrid project.
 *
 * 2007-2009 University of Maryland (http://www.umd.edu)
 * (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <julien@linuxwall.info> for the University of Maryland)
 *
 * 2012-2013 University of Connecticut (http://www.uconn.edu)
 * (Extended by Tamas K Lengyel <tamas.k.lengyel@gmail.com>
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

#ifndef __LOG_H_
#define __LOG_H_

#include "types.h"
#include "structs.h"
#include "globals.h"

#define L(sdata,ddata,level,id) \
	if (0 != honeylog(sdata,ddata,level,id)) \
	{g_printerr("******LOG ENGINE ERROR******\n");}

#define printdbg(...) \
    if(debug) { \
    	g_mutex_lock(&log_header_lock); \
    	g_printerr (__VA_ARGS__); \
    	g_mutex_unlock(&log_header_lock); \
    }

// Should only be used with printerr()
#define H(id) log_header(__func__, id)
static inline const char* log_header(const char* function_name, int id) {
    struct tm *tm;
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    tm = localtime(&tv.tv_sec);
    if (tm == NULL) {
        perror("localtime");
        return '\0';
    }
    snprintf(log_header_string, 200,
            "%d-%02d-%02d %02d:%02d:%02d.%.6d;%6u;%s:\t", (1900 + tm->tm_year),
            (1 + tm->tm_mon), tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,
            (int) tv.tv_usec, id, function_name);
    return log_header_string;
}

status_t honeylog(char *sdata, char *ddata, log_verbosity_t level, unsigned id);

int open_debug_log(void);

int close_debug_log(void);

void open_connection_log(void);

int close_connection_log(void);

//void rotate_log(int signal_nb, void *siginfo, void *context);
void rotate_connection_log(int signal_nb);

//void connection_stat(struct conn_struct *conn);
void connection_log();

status_t log_mysql(const struct conn_struct *conn, const GString *proto,
        const GString *status, GString **status_info, gdouble duration);

status_t log_csv(const struct conn_struct *conn, const GString *proto,
        const GString *status, GString **status_info, gdouble duration,
        output_t output);

status_t log_std(const struct conn_struct *conn, const GString *proto,
        const GString *status, GString **status_info, gdouble duration,
        output_t output);

status_t init_mysql_log();

#endif ///__LOG_H_
