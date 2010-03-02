 /*
  config {
    parameter = value;
  }

  module "<identifier>" {
    parameter = value;
  }
 
  target "net 10.0.0.0/16 and port 22" {	# pcap filter string
    frontend 192.168.0.16/30:80 "accept rule defined by an equation of module identifiers"   # will potentially use a NAT engine to proxy
    backend 192.168.0.200:80 "accept rule defined by an equation of module identifiers" # will use a REDIRECTION engine
    control "control rule defined by an equation of module identifiers"
  }
 
 */

%{
#include <stdio.h>
#include <pcap.h>
#include <dumbnet.h>
#include <glib.h>
#include "rules.h"

#define YY_NO_INPUT
%}

%option nounput

%%

	/* Honeybrid configuration keywords */
config		{ return CONFIGURATION; }
target		{ return TARGET; }
module		{ return MODULE; }
filter		{ return FILTER; }
frontend 	{ return FRONTEND; }
backend  	{ return BACKEND; }
limit 	 	{ return LIMIT; }

	/* Delimiters */
"{"		{ return OPEN; }
"}"		{ return END; }
";"		{ return SEMICOLON; }
"\""		{ return QUOTE; }
":"|"="         { yylval.string = strdup(yytext); return EQ; }

	/* Content Variables */
[0-9]+				{ yylval.number = atoi(yytext); return NUMBER; }
[a-zA-Z0-9_-]+			{ yylval.string = strdup(yytext); return WORD; }
[a-zA-Z0-9()<>|&^!\/._-]+	{ yylval.string = strdup(yytext); return EXPR; }

	/* Ignored */
"//"[^\n]* 	/* ignored */	
"#"[^\n]*  	/* ignored */
\n	   	{ yylineno++; }  
[ \t]+	   	/* ignore white space */ 







	/* Reduced PCAP filter */
	/* No longer useful because we're using pcap_compile to interpret the filter
	any                     { return ANY; }
	ip|host                 { return IP; }
	hostname                { return HOSTNAME; }
	proto                   { return PROTO; }
	net                     { return NET; }
	port                    { return PORT; }
	and|"&&"                { return AND; }
	or|"||"                 { return OR; }
	not|"!"                 { return NOT; }
	src                     { return SRC; }
	dst                     { return DST; }
	in                      { return IN; }
	*/

	/*
 if                      { return IF; }
 ident                   { return IDENT; }
 out                     { return OUT; }
 flags                   { return FLAGS; }
 tos                     { return TOS; }
 as                      { return AS; }
 packets                 { return PACKETS; }
 bytes                   { return BYTES; }
 bpp                     { return BPP; }
 bps                     { return BPS; }
 pps                     { return PPS; }
 duration                { return DURATION; }
 ipv4|inet               { return IPV4; }
 ipv6|inet6              { return IPV6; }
 icmp-type               { return ICMP_TYPE; }
 icmp-code               { return ICMP_CODE; }
	*/

	/* Delimiters */
	/* "\."		{ return DOT; } */
	/* ":"|"="|"=="|eq             { return EQ; } */
	/* ">"|gt                  { return GT; }
	   "<"|lt                  { return LT; }
	*/
	/*
	and|"&&"                { return AND; }
	or|"||"                 { return OR; }
	not|"!"                 { return NOT; }
	*/

	/* Content Variables */
	/* [a-zA-Z0-9\/._-]+	{ yylval.string = strdup(yytext); return WORD; } */
	/* [a-zA-Z0-9()<>|&^!\/._-]+	{ yylval.string = strdup(yytext); return WORD; } */

%%
