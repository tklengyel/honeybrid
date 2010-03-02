%{
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <pcap.h>
#include <dumbnet.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "tables.h"
#include "types.h"
#include "decision_engine.h"
#include <sys/stat.h>
#include <fcntl.h>

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
	| configuration config { 	g_printerr("Main config parsed\n"); }
	| configuration module {	g_printerr("Module parsed\n"); }
	| configuration target {	g_printerr("Target parsed\n"); }
	;




config: CONFIGURATION OPEN parameters END { /* nothing to do */ }
	;

parameters: { /* nothing to do */ }
	| parameters parameter SEMICOLON { /* nothing to do */  }
	;

parameter: WORD EQ WORD {
		g_hash_table_insert(config, $1, $3);
		g_printerr("\t'%s' => '%s'\n", $1, $3);
	}
	|  WORD EQ EXPR {
		g_hash_table_insert(config, $1, $3);
                g_printerr("\t'%s' => '%s'\n", $1, $3);
	}
	|  WORD EQ NUMBER {
		//char *s = malloc(sizeof($3));
		char *s = malloc(128);
		snprintf(s, 128, "%d",$3);
		g_hash_table_insert(config, $1, s);
		g_printerr("\t'%s' => '%d'\n", $1, $3);
        }
	;





module: MODULE QUOTE WORD QUOTE OPEN settings END {
		g_hash_table_insert(module, $3, $6);
		g_printerr("\tmodule '%s' defined with %d parameters\n", $3, g_hash_table_size((GHashTable *)$6));
		if (NULL == g_hash_table_lookup((GHashTable *)$6, "function")) {
			errx(1, "%s: Fatal error: missing parameter 'function' in module '%s'\n", __func__, $3);
		} else {
			//g_printerr("\tModule function defined as '%s'\n", (char *)g_hash_table_lookup((GHashTable *)$6, "function"));
			////g_hash_table_replace((GHashTable *)$6, "function", get_module((char *)g_hash_table_lookup((GHashTable *)$6, "function")));
			g_hash_table_insert((GHashTable *)$6, "function_pointer", get_module((char *)g_hash_table_lookup((GHashTable *)$6, "function")));
			//g_printerr("\tModule function defined at address %p\n", g_hash_table_lookup((GHashTable *)$6, "function"));
		}
		
		gchar *backup_file;
		if (NULL != (backup_file = (char *)g_hash_table_lookup((GHashTable *)$6, "backup_file"))) {
			int backup_fd;
			GError *error = NULL;
			GKeyFile *backup = NULL;
			backup = g_key_file_new();
			g_key_file_set_list_separator(backup, '\t');
			/*! We store a pointer to GKeyFile object in the module hash table */
			g_hash_table_insert((GHashTable *)$6, "backup", backup);
			g_printerr("\t%s: New GKeyFile %p created\n", __func__, backup);
			/*! We then check if the file exists. Otherwise we create it */
			if (FALSE == g_file_test(backup_file, G_FILE_TEST_IS_REGULAR)) {
				if (-1 == (backup_fd = g_open(backup_file, O_WRONLY | O_CREAT | O_TRUNC, NULL))) {
					errx(1, "%s: Fatal error, can't create backup file for module", __func__);
				} else {
					//g_hash_table_insert((GHashTable *)$6, "backup_fd", &backup_fd);
					close(backup_fd);
				}
			} else {
				/*! If the file exists, we try to load it into memory */
				/*! \todo free all these structures, and close file descriptor when exiting */
				if (FALSE == g_key_file_load_from_file(
					g_hash_table_lookup((GHashTable *)$6, "backup"),
					backup_file,
					G_KEY_FILE_KEEP_COMMENTS,
					&error)) {
					g_printerr("\t%s: can't load backup file for module: %s\n", __func__, error->message);
				}
			}
			//g_free(backup_file);
		}
	}
	;

settings: { 
		if (NULL == ($$ = (struct GHashTable *)g_hash_table_new(g_str_hash, g_str_equal)))
	                errx(1, "%s: Fatal error while creating module hash table.\n", __func__);
	}
	| settings WORD EQ WORD SEMICOLON {
		if (g_strcmp0($2, "function") == 0) {
			/*! We store a pointer to the module function in the module hash table 
			    If the module function isn't defined in get_module(), the application will exit and display an error message */
                        g_hash_table_insert((GHashTable *)$$, "function", $4);
		}
		if (g_strcmp0($2, "backup") == 0) {
			GString *tmp = g_string_new($4);
                        g_hash_table_insert((GHashTable *)$$, "backup_file", g_string_free(tmp, FALSE));
		}
		g_hash_table_insert((GHashTable *)$$, $2, $4);
                g_printerr("\t'%s' => '%s'\n", $2, $4);
	}
	| settings WORD EQ EXPR SEMICOLON {
		if (g_strcmp0($2, "function") == 0) {
			/*! We store a pointer to the module function in the module hash table 
			    If the module function isn't defined in get_module(), the application will exit and display an error message */
                        g_hash_table_insert((GHashTable *)$$, "function", $4);
		}
		if (g_strcmp0($2, "backup") == 0) {
			GString *tmp = g_string_new($4);
                        g_hash_table_insert((GHashTable *)$$, "backup_file", g_string_free(tmp, FALSE));
		}
		g_hash_table_insert((GHashTable *)$$, $2, $4);
                g_printerr("\t'%s' => '%s'\n", $2, $4);
	}
	| settings WORD EQ NUMBER SEMICOLON {
		char *s = malloc(sizeof($4));
                sprintf(s, "%d",$4);
                g_hash_table_insert((GHashTable *)$$, $2, s);
                g_printerr("\t'%s' => '%d'\n", $2, $4);
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
		g_printerr("\tGoing to add new element to target array...\n");
		g_ptr_array_add(targets, $3);
		g_printerr("\t...done\n");
		g_printerr("\tAdded a new target with the following values:\n\tfront_handler: %s\n\tfront_rule: %s\n\tback_handler: %s\n\tback_rule: %s\n",
				//addr_ntoa($3->front_handler), "-", //$3->front_rule->module_name->str,
				//addr_ntoa($3->back_handler), "-"); //$3->back_rule->module_name->str);
				addr_ntoa($3->front_handler),($3->front_rule == NULL) ? "(null)" : $3->front_rule->module_name->str,
				addr_ntoa($3->back_handler), ($3->back_rule  == NULL) ? "(null)" : $3->back_rule->module_name->str);
	}
	;

rule: 	{
		g_printerr("\tAllocating memory for new structure 'target'\n");
		$$ = malloc(sizeof(struct target));
		$$->front_handler = (struct addr *)g_malloc0(sizeof(struct addr));
		$$->back_handler = (struct addr *)g_malloc0(sizeof(struct addr));
		$$->front_rule = NULL;
		$$->back_rule = NULL;
		$$->control_rule = NULL;

	}
	| rule FILTER QUOTE equation QUOTE SEMICOLON {
		//g_printerr("Read pcap filter: '%s'\n", $4);
		//g_printerr("Read pcap filter: '%s'\n", g_string_free($4, FALSE));
		//if (pcap_compile_nopcap(1500, LINKTYPE, $$->filter, $4->str, 1, 0) < 0) {
		$$->filter = malloc(sizeof(struct bpf_program));
		if (pcap_compile_nopcap(1500, LINKTYPE, $$->filter, $4->str, 1, 0) < 0) {
			g_printerr("\tPCAP ERROR: '%s'\n", $4->str);
                	yyerror("\tIncorrect pcap filter");
		}
		g_printerr("\tPCAP filter compiled:%s\n", $4->str);	
		g_string_free($4, TRUE);
	}
	| rule FRONTEND honeynet SEMICOLON {
		$$->front_handler = $3;
		g_printerr("\tIP %s (%d) copied to handler\n", addr_ntoa($3), $3->addr_ip);
		g_printerr("\tResult IP %s (%d)\n", addr_ntoa($$->front_handler), $$->front_handler->addr_ip);
		$$->front_rule = NULL;
	} 
	| rule FRONTEND honeynet QUOTE equation QUOTE SEMICOLON {
		$$->front_handler = $3;
		g_printerr("\tIP %s (%d) copied to handler\n", addr_ntoa($3), $3->addr_ip);
		$$->front_rule = DE_create_tree($5->str);
		g_string_free($5, TRUE);
	}
	| rule BACKEND honeynet QUOTE equation QUOTE SEMICOLON {
		$$->back_handler = $3;
		g_printerr("\tIP %s (%d) copied to handler\n", addr_ntoa($3), $3->addr_ip);
		$$->back_rule = DE_create_tree($5->str);
		g_string_free($5, TRUE);
	}
	| rule LIMIT QUOTE equation QUOTE SEMICOLON {
		$$->control_rule = DE_create_tree($4->str);
		g_string_free($4, TRUE);
	}
	;

honeynet: EXPR { 
		if (addr_pton($1, $$) < 0)
                        yyerror("\tIllegal IP address");
		else 
			g_printerr("\tIP %s (%d) added as honeypot\n", addr_ntoa($$), $$->addr_ip);
                //g_free($1);
	}
	;

	/* TODO: debug string concatenation... use g_string? */
equation: { 
		//$$ = malloc(sizeof(char));
		//snprintf($$, 1, " ");
		$$ = g_string_new("");
	}
	| equation WORD {
		if ($$->len > 0) { g_string_append_printf($$, " "); }
		$$ = g_string_append($$, $2);
		//$$ = str_append($$, " ");
		//$$ = str_append($$, $2);
	 }
	| equation NUMBER { 
		if ($$->len > 0) { g_string_append_printf($$, " "); }
		g_string_append_printf($$, "%d", $2);
		//$$ = str_append($$, " ");
		//$$ = int_append($$, $2);
	 }
	| equation EXPR { 
		if ($$->len > 0) { g_string_append_printf($$, " "); }
		$$ = g_string_append($$, $2);
		//$$ = str_append($$, " ");
		//$$ = str_append($$, $2);
	 }
	| equation EQ { 
		if ($$->len > 0) { g_string_append_printf($$, " "); }
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

