%{
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <pcap.h>
#include <dumbnet.h>
#include <glib.h>
#include "tables.h"
#include "types.h"
#include "decision_engine.h"

/*! Type of capture link */
#define LINKTYPE 1 	//LINKTYPE_ETHERNET=1 \todo dynamically assign link type from nfqueue

enum { SOURCE = 1, DESTINATION, SOURCE_AND_DESTINATION, SOURCE_OR_DESTINATION };
extern int  yylineno;
extern char *yytext;
static void yyerror(const char *msg);

int yylex(void);

int yywrap() {
	/*! should return 0 if additional input has to be parsed, 1 if the end has been reached */
	return 1;
}

char* str_append(char * root, char * str);
char* int_append(char * root, int num);

%}

/* Delimiters */
%token OPEN END SEMICOLON QUOTE DOT

/* Honeybrid configuration keywords */
%token MODULE FILTER FRONTEND BACKEND LIMIT CONFIGURATION TARGET

/* Content Variables */
%token <number> NUMBER
%token <string> WORD
%token <string> EQ
%token <string> EXPR

%type <hash>    settings
%type <target>  rule
%type <gstring>  equation 
%type <addr>    honeynet

%union {
	int    number;
	char * string;
	GString * gstring;
	struct GHashTable * hash;
	struct target * target;
	struct addr * addr;
}

/*
  config {
    parameter = value;
  }

  module "<identifier>" {
    parameter = value;
  }
 
  target "net 10.0.0.0/16 and port 22" {        # pcap filter string
    frontend 192.168.0.16/30 "accept rule defined by an equation of module identifiers (identifiers separated by 'or' or 'and') "   # will potentially use a NAT engine to proxy
    backend 192.168.0.200 "accept rule defined by an equation of module identifiers" # will use a REDIRECTION engine
    control "control rule defined by an equation of module identifiers"
  }
 
*/

%%
configuration:	/* empty */
	| configuration config { 	g_printerr("%s: config parsed\n", __func__); }
	| configuration module {	g_printerr("%s: module parsed\n", __func__); }
	| configuration target {	g_printerr("%s: target parsed\n", __func__); }
	;




config: CONFIGURATION OPEN parameters END { /* nothing to do */ }
	;

parameters: { /* nothing to do */ }
	| parameters parameter SEMICOLON { /* nothing to do */  }
	;

parameter: WORD EQ WORD {
		g_hash_table_insert(config, $1, $3);
		g_printerr("\tparameter '%s' has value '%s'\n", $1, $3);
	}
	|  WORD EQ EXPR {
		g_hash_table_insert(config, $1, $3);
                g_printerr("\tparameter '%s' has value '%s'\n", $1, $3);
	}
	|  WORD EQ NUMBER {
		//char *s = malloc(sizeof($3));
		char *s = malloc(128);
		snprintf(s, 128, "%d",$3);
		g_hash_table_insert(config, $1, s);
		g_printerr("\tparameter '%s' has value '%d'\n", $1, $3);
        }
	;





module: MODULE QUOTE WORD QUOTE OPEN settings END {
		g_hash_table_insert(module, $3, $6);
		g_printerr("\tmodule '%s' defined with %d parameters\n", $3, g_hash_table_size((GHashTable *)$6));
	}
	;

settings: { 
		if (NULL == ($$ = (struct GHashTable *)g_hash_table_new(g_str_hash, g_str_equal)))
	                errx(1,"%s: Fatal error while creating module hash table.\n", __func__);
	}
	| settings WORD EQ WORD SEMICOLON {
		g_hash_table_insert((GHashTable *)$$, $2, $4);
                g_printerr("\tparameter '%s' has value '%s'\n", $2, $4);
	}
	| settings WORD EQ NUMBER SEMICOLON {
		char *s = malloc(sizeof($4));
                sprintf(s, "%d",$4);
                g_hash_table_insert((GHashTable *)$$, $2, s);
                g_printerr("\tparameter '%s' has value '%d'\n", $2, $4);
	}
	;





/*
target: TARGET OPEN filter END OPEN rule END {
*/
target: TARGET OPEN rule END {
		/*
		if (pcap_compile_nopcap(1500, LINKTYPE, $6->filter, $3, 1, 0) < 0) {
			g_printerr("PCAP ERROR: '%s'\n", $3);
                	yyerror("bad pcap filter");
		}
		*/
		//g_printerr("Going to add new elemento to targets array...\n");
		g_ptr_array_add(targets, $3);
		//g_printerr("...done\n");
	}
	;

rule: 	{
		g_printerr("Allocating memory for new structure 'target'\n");
		$$ = malloc(sizeof(struct target));
	}
	| rule FILTER QUOTE equation QUOTE SEMICOLON {
		//g_printerr("Read pcap filter: '%s'\n", $4);
		//g_printerr("Read pcap filter: '%s'\n", g_string_free($4, FALSE));
		//if (pcap_compile_nopcap(1500, LINKTYPE, $$->filter, $4->str, 1, 0) < 0) {
		$$->filter = malloc(sizeof(struct bpf_program));
		if (pcap_compile_nopcap(1500, LINKTYPE, $$->filter, $4->str, 1, 0) < 0) {
			g_printerr("PCAP ERROR: '%s'\n", $4->str);
                	yyerror("incorrect pcap filter");
		}
		g_printerr("PCAP filter compiled:%s\n", g_string_free($4, FALSE));	
	}
	| rule FRONTEND honeynet QUOTE equation QUOTE SEMICOLON {
		$$->front_handler = $3;
		//$$->front_rule = DE_create_tree($5);
		$$->front_rule = DE_create_tree(g_string_free($5, FALSE));
	}
	| rule BACKEND honeynet QUOTE equation QUOTE SEMICOLON {
		$$->back_handler = $3;
		//$$->back_rule = DE_create_tree($5);
		$$->back_rule = DE_create_tree(g_string_free($5,  FALSE));
	}
	| rule LIMIT QUOTE equation QUOTE SEMICOLON {
		//$$->control_rule = DE_create_tree($4);
		$$->control_rule = DE_create_tree(g_string_free($4, FALSE));
	}
	;

honeynet: EXPR { 
		if (addr_pton($1, $$) < 0)
                        yyerror("Illegal IP address");
                free($1);
	}
	;

	/* TODO: debug string concatenation... use g_string? */
equation: { 
		//$$ = malloc(sizeof(char));
		//snprintf($$, 1, " ");
		$$ = g_string_new("");
	}
	| equation WORD {
		g_string_append_printf($$, " ");
		$$ = g_string_append($$, $2);
		//$$ = str_append($$, " ");
		//$$ = str_append($$, $2);
	 }
	| equation NUMBER { 
		g_string_append_printf($$, " ");
		g_string_append_printf($$, "%d", $2);
		//$$ = str_append($$, " ");
		//$$ = int_append($$, $2);
	 }
	| equation EXPR { 
		g_string_append_printf($$, " ");
		$$ = g_string_append($$, $2);
		//$$ = str_append($$, " ");
		//$$ = str_append($$, $2);
	 }
	| equation EQ { 
		g_string_append_printf($$, " ");
		$$ = g_string_append($$, $2);
		//$$ = str_append($$, " ");
		//$$ = str_append($$, $2);
	 }
	;

%%

static void  yyerror(const char *msg) {
        errx(1,"line %d: %s at '%s'", yylineno, msg, yytext);
}

char* str_append(char * root, char * str) {
	g_printerr("\t##[1] root: %s, str: %s\n", root, str);
		char *tmp = (char *)calloc(strlen(root) + strlen(str), sizeof(char));
  		strcpy(tmp, root);
  		strncat(tmp, str, strlen(root) + strlen(str));
		root = realloc(root, strlen(root) + strlen(str));
		strcpy(root, tmp);
		free(tmp);
	g_printerr("\t##[1] root: %s\n\t=====================\n", root);
		return root;
}
char* int_append(char * root, int number) {
	g_printerr("\t##[1] root: %s, num: %d\n", root, number);
		char *num = malloc(128);
		sprintf(num, "%d", number);
		char *tmp = (char *)calloc(strlen(root) + strlen(num), sizeof(char));
  		strcpy(tmp, root);
  		strncat(tmp, num, strlen(root) + strlen(num));
		root = tmp;
		free(tmp);
		free(num);
	g_printerr("\t##[1] root: %s\n\t=====================\n", root);
		return root;
}

