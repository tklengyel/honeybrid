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
#include <sys/stat.h>
#include <fcntl.h>
#include <config.h>
#include "globals.h"
#include "structs.h"
#include "convenience.h"
#include "decision_engine.h"
#include "modules.h"
#include "log.h"

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
%token MODULE FILTER FRONTEND BACKEND BACKPICK LIMIT CONFIGURATION TARGET LINK HW

/* Content Variables */
%token <number> NUMBER
%token <string> WORD
%token <string> EQ
%token <string> EXPR

%type <hash>    	module_settings
%type <interface>   link_settings
%type <target>  	rule
%type <gstring>  	equation 
%type <addr>    	honeynet
%type <addr> 		mac

%union {
	int    number;
	char * string;
	GString * gstring;
	struct GHashTable * hash;
	struct interface * interface;
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
	| configuration link { 		g_printerr("Network link parsed\n"); }
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
		g_free($2);
	}
	|  WORD EQ EXPR {
		g_hash_table_insert(config, $1, $3);
        g_printerr("\t'%s' => '%s'\n", $1, $3);
        g_free($2);
	}
	|  WORD EQ NUMBER {
		int *d =g_malloc(sizeof(int));
		*d = $3;
		g_hash_table_insert(config, $1, d);
		g_printerr("\t'%s' => %i\n", $1, *d);
		g_free($2);
    }
	|  WORD EQ QUOTE honeynet QUOTE {
		char *s = g_malloc0(snprintf(NULL, 0, "%s", addr_ntoa($4)) + 1);
		sprintf(s, "%s", addr_ntoa($4));
        g_hash_table_insert(config, $1, s);
        g_printerr("\tDefining IP: '%s' => '%s'\n", $1, s);
		free($4);
		g_free($2);
    }
	;



link: LINK QUOTE WORD QUOTE OPEN link_settings END { 
        struct interface *iface=(struct interface *)$6;
        if(iface) {
            iface->tag=$3;
            iface->id = link_count;
            link_count++;
            
            g_printerr("\t'tag' => '%s'\n", $3);
            
            g_hash_table_insert(links, iface->tag, iface);
        } else {
            errx(1, "Link configuration is incomplete!\n");
        }
    }
    ;

link_settings: {
        if (NULL == ($$ = g_malloc0(sizeof(struct interface))))
            errx(1, "%s: Fatal error while creating link table.\n", __func__);
    }
    | link_settings WORD EQ QUOTE WORD QUOTE SEMICOLON {
        if(strcmp($2, "interface")) {
            errx(1, "Unrecognized option: %s. Did you mean: 'interface'?\n", $2); 
        }
        struct interface *iface=(struct interface *)$$;
        iface->name = $5;
        g_printerr("\t'%s' => '%s'\n", $2, iface->name);
        g_free($2);
        g_free($3);
    }
	|  link_settings WORD EQ NUMBER SEMICOLON {
		if(strcmp($2, "promisc")) {
            errx(1, "Unrecognized option: %s. Did you mean: 'promisc'?\n", $2); 
        }
        struct interface *iface=(struct interface *)$$;
        iface->promisc = $4;
        g_printerr("\t'%s' => %i\n", $2, $4);
        
		g_free($2);
		g_free($3);
    }
    | link_settings FILTER EQ QUOTE equation QUOTE SEMICOLON {

		$$->filter = strdup($5->str);
		g_printerr("\tPCAP filter:%s\n", $5->str);	
		g_string_free($5, TRUE);
		g_free($3);
	}
    ;

module: MODULE QUOTE WORD QUOTE OPEN module_settings END {
		g_hash_table_insert(module, $3, $6);
		g_printerr("\tmodule '%s' defined with %d parameters\n", $3, g_hash_table_size((GHashTable *)$6));
		if (NULL == g_hash_table_lookup((GHashTable *)$6, "function")) {
			errx(1, "%s: Fatal error: missing parameter 'function' in module '%s'\n", __func__, $3);
		}
		
		gchar *backup_file = NULL;
		if (NULL != (backup_file = (gchar *)g_hash_table_lookup((GHashTable *)$6, "backup"))) {
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

module_settings: { 
		if (NULL == ($$ = (struct GHashTable *)g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free)))		
	    	errx(1, "%s: Fatal error while creating module hash table.\n", __func__);
	}
	| module_settings WORD EQ WORD SEMICOLON {
	    g_hash_table_insert((GHashTable *)$$, $2, $4);
	    g_printerr("\t'%s' => '%s'\n", $2, $4);
	    g_free($3);
	}
	| module_settings WORD EQ EXPR SEMICOLON {
		g_hash_table_insert((GHashTable *)$$, $2, $4);
        g_printerr("\t'%s' => '%s'\n", $2, $4);
        g_free($3);
	}
	| module_settings WORD EQ NUMBER SEMICOLON {
		int *d = g_malloc0(sizeof(int));
        *d = $4;
        g_hash_table_insert((GHashTable *)$$, $2, d);
        g_printerr("\t'%s' => %i\n", $2, *d);
        g_free($3);
	}
	;

target: TARGET QUOTE WORD QUOTE OPEN rule END {

		struct interface *iface = g_hash_table_lookup(links, $3);
		if(iface == NULL) {
			yyerror("\tTarget interface is not defined!\n");
		}
		
		if(NULL != g_hash_table_lookup(targets, $3)) {
			yyerror("\tThis link is already assigned to a target!\n");
		}
		
		$6->default_route=iface;
		
		printdbg("\tAdding target with default link '%s'\n", $3);
		g_hash_table_insert(targets, $3, $6);
	}
	;

rule: 	{
		$$ = (struct target *)g_malloc0(sizeof(struct target));
		
		// This tree holds the main backend structures
		$$->back_handlers = g_tree_new_full((GCompareDataFunc)intcmp, NULL, g_free, (GDestroyNotify)free_handler);
		
		// This table just contains the unique backend IP's
		// The key (char *ip) lives in the struct allocated for back_handlers so don't free it here
		$$->unique_backend_ips = g_hash_table_new(g_str_hash, g_str_equal);
	}
	| rule FRONTEND QUOTE WORD QUOTE honeynet HW mac SEMICOLON {
		$$->front_handler = g_malloc0(sizeof(struct handler));
		$$->front_handler->iface = g_hash_table_lookup(links, $4);
		
		if($$->front_handler->iface == NULL) {
			yyerror("Front handler interface is undefined!\n");
		}
		
		$$->front_handler->ip=$6;
		$$->front_handler->mac=$8;
		
        char *mac = addr_ntoa($$->front_handler->mac);
		g_printerr("\tFrontend defined at %s hw %s on '%s'\n", addr_ntoa($6), mac, $4);
		g_free($4);	
	} 
	| rule FRONTEND QUOTE WORD QUOTE honeynet HW mac QUOTE equation QUOTE SEMICOLON {
	
		$$->front_handler = g_malloc0(sizeof(struct handler));
		$$->front_handler->iface = g_hash_table_lookup(links, $4);
		
		if($$->front_handler->iface == NULL) {
			yyerror("Front handler interface is undefined!\n");
		}
		
		$$->front_handler->ip=$6;
		$$->front_handler->mac=$8;
		$$->front_handler->rule = DE_create_tree($10->str);
		
		$$->front_handler->ip_str=g_malloc0(snprintf(NULL, 0, "%s", addr_ntoa($6)) + 1);
        sprintf($$->front_handler->ip_str, "%s", addr_ntoa($6));
		
        char *mac = addr_ntoa($$->front_handler->mac);
		g_printerr("\tFrontend defined at %s hw %s on '%s' with rule: %s\n", $$->front_handler->ip_str, mac, $4, $10->str);
		g_free($4);
		g_string_free($10, TRUE);
	}
	| rule BACKPICK QUOTE equation QUOTE SEMICOLON {
        g_printerr("\tCreating backend picking rule: %s\n", $4->str);
		$$->back_picker = DE_create_tree($4->str);
		g_string_free($4, TRUE);
    }
	| rule BACKEND QUOTE WORD QUOTE honeynet HW mac SEMICOLON {
    	if($$->back_picker == NULL) {
    		yyerror("Backend needs a rule if no backend picking rule is defined!\n");
    	}
    		
    	struct interface *iface = g_hash_table_lookup(links, $4);
    	if(iface == NULL) {
    		yyerror("Back handler interface is undefined!\n");
    	}	
    		
    	// This will be freed automatically when the tree is destroyed
    	$$->back_handler_count++;
    	uint32_t *key=malloc(sizeof(uint32_t));
    	*key=$$->back_handler_count;
    		
    	struct handler *back_handler = g_malloc0(sizeof(struct handler));
    	back_handler->iface=iface;
    
        back_handler->ip=$6;
        back_handler->ip_str=g_malloc0(snprintf(NULL, 0, "%s", addr_ntoa($6)) + 1);
       	back_handler->mac = $8;
        sprintf(back_handler->ip_str, "%s", addr_ntoa($6));
    
    	g_tree_insert($$->back_handlers, key, back_handler);
    	g_hash_table_insert($$->unique_backend_ips, back_handler->ip_str, NULL);
    		
        char *mac = addr_ntoa(back_handler->mac);
    	g_printerr("\tBackend #%u defined at %s hw %s on '%s' copied to handler without rule\n",
    		*key, back_handler->ip_str, mac, $4);
    		
    	g_free($4);
    }
	| rule BACKEND QUOTE WORD QUOTE honeynet HW mac QUOTE equation QUOTE SEMICOLON {

		struct interface *iface = g_hash_table_lookup(links, $4);
    	if(iface == NULL) {
    		yyerror("Back handler interface is undefined!\n");
    	}
    	
    	// This will be freed automatically when the tree is destroyed
        $$->back_handler_count++;
        uint32_t *key=malloc(sizeof(uint32_t));
        *key=$$->back_handler_count;
            
        struct handler *back_handler = g_malloc0(sizeof(struct handler));
        back_handler->iface=g_hash_table_lookup(links, $4);
    
        back_handler->ip=$6;
        back_handler->mac = $8;
        back_handler->rule=DE_create_tree($10->str);
        back_handler->ip_str=g_malloc0(snprintf(NULL, 0, "%s", addr_ntoa($6)) + 1);
        sprintf(back_handler->ip_str, "%s", addr_ntoa($6));
    
    	g_tree_insert($$->back_handlers, key, back_handler);
    	g_hash_table_insert($$->unique_backend_ips, back_handler->ip_str, NULL);
        
        char *mac = addr_ntoa(back_handler->mac);
        g_printerr("\tBackend #%u defined at %s hw %s on '%s' with rule: %s\n", *key, back_handler->ip_str,
        	mac, $4, $10->str);
                
        g_string_free($10, TRUE);
        g_free($4);
    }
//TODO
/*
	| rule BACKEND QUOTE equation QUOTE honeynet QUOTE equation QUOTE SEMICOLON {

            // This will be freed automatically when the tree is destroyed
            $$->backends++;
            uint32_t *key=malloc(sizeof(uint32_t));
            *key=$$->backends;
            
            struct backend *back_handler = g_malloc0(sizeof(struct backend));
            back_handler->iface=g_malloc0(sizeof(struct interface));

            back_handler->iface->tag=g_strdup($4->str);
		    back_handler->iface->name=g_strdup($8->str);
		    back_handler->iface->mark=*key; // Automatically assign iptables mark
		    back_handler->iface->ip=$6;
		    //back_handler->iface->ip_str=g_malloc0(snprintf(NULL, 0, "%s", addr_ntoa($6)) + 1);
		    //sprintf(back_handler->iface->ip_str, "%s", addr_ntoa($6));
		    
            g_printerr("\tBackend #%u at %s on interface %s and tag %s: no rule\n",
                *key, back_handler->iface->ip_str, back_handler->iface->name, back_handler->iface->tag);

            g_tree_insert($$->back_handlers, key, back_handler);
            g_hash_table_insert($$->unique_backend_ips, back_handler->iface->ip_str, NULL);
                
            g_string_free($4, TRUE);
		    g_string_free($8, TRUE);
        }
	| rule BACKEND QUOTE equation QUOTE honeynet QUOTE equation QUOTE QUOTE equation QUOTE SEMICOLON {
              
             // This will be freed automatically when the tree is destroyed
            $$->backends++;
            uint32_t *key=malloc(sizeof(uint32_t));
            *key=$$->backends;
            
            struct backend *back_handler = g_malloc0(sizeof(struct backend));
            back_handler->iface=g_malloc0(sizeof(struct interface));
            
            back_handler->iface->tag=g_strdup($4->str);
		    back_handler->iface->name=g_strdup($8->str);
		    back_handler->iface->mark=*key; // Automatically assign iptables mark
		    back_handler->iface->ip=$6;
		    //back_handler->iface->ip_str=g_malloc0(snprintf(NULL, 0, "%s", addr_ntoa($6)) + 1);
            //sprintf(back_handler->iface->ip_str, "%s", addr_ntoa($6));
            
            g_printerr("\tBackend #%u at IP %s on interface %s and tag %s: %s\n", 
                *key, back_handler->iface->ip_str, back_handler->iface->name, back_handler->iface->tag, $11->str);
            
            back_handler->rule=DE_create_tree($11->str);
            
            g_tree_insert($$->back_handlers, key, back_handler);
            g_hash_table_insert($$->unique_backend_ips, back_handler->iface->ip_str, NULL);

            g_string_free($4, TRUE);
		    g_string_free($8, TRUE);
		    g_string_free($11, TRUE);
        }*/
	| rule LIMIT QUOTE equation QUOTE SEMICOLON {
		$$->control_rule = DE_create_tree($4->str);
		g_string_free($4, TRUE);
	}

honeynet: EXPR {
        $$ = (struct addr *)g_malloc0(sizeof(struct addr));
		if (addr_pton($1, $$) < 0) {
            yyerror("\tIllegal IP address");
        }
        g_free($1);
	}
	
mac: EXPR {
		$$ = (struct addr *)g_malloc0(sizeof(struct addr));
		if (addr_pton($1, $$) < 0) {
            yyerror("\tIllegal MAC address");
        }
        g_free($1);
	}
	;

equation: { 
		$$ = g_string_new("");
	}
	| equation WORD {
		if ($$->len > 0) { g_string_append_printf($$, " "); }
		$$ = g_string_append($$, $2);
		g_free($2);
	 }
	| equation NUMBER { 
		if ($$->len > 0) { g_string_append_printf($$, " "); }
		g_string_append_printf($$, "%d", $2);
	 }
	| equation EXPR { 
		if ($$->len > 0) { g_string_append_printf($$, " "); }
		$$ = g_string_append($$, $2);
		g_free($2);
	 }
	| equation EQ { 
		if ($$->len > 0) { g_string_append_printf($$, " "); }
		$$ = g_string_append($$, $2);
		g_free($2);
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

