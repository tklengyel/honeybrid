%{
#include <glib/gstdio.h>
#include <fcntl.h>
#include "globals.h"
#include "structs.h"
#include "convenience.h"
#include "decision_engine.h"
#include "modules.h"
#include "log.h"
#include "management.h"

extern int  yylineno;
extern char *yytext;
static void yyerror(const char *msg);

int yylex(void);

int yywrap() {
	/*! should return 0 if additional input has to be parsed, 1 if the end has been reached */
	return 1;
}

%}

/* Delimiters */
%token OPEN END SEMICOLON QUOTE DOT

/* Honeybrid configuration keywords */
%token MODULE FILTER FRONTEND BACKEND
%token BACKPICK INTERNET CONFIGURATION 
%token TARGET LINK HW VLAN DEFAULT 
%token ROUTE VIA NETMASK INTERNAL
%token WITH EXCLUSIVE INTRALAN

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
%type <addr> 		netmask
%type <number>		vlan

%union {
	int    number;
	char * string;
	GString * gstring;
	struct GHashTable * hash;
	struct interface * interface;
	struct target * target;
	struct addr * addr;
}

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
			g_hash_table_insert((GHashTable *)$6, g_strdup("backup"), backup);
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

target: TARGET OPEN rule END {
        add_target($3);
    }
    | TARGET DEFAULT ROUTE VIA QUOTE WORD QUOTE mac OPEN rule END {

		struct interface *iface = g_hash_table_lookup(links, $6);
		if(iface == NULL) {
			yyerror("\tTarget interface is not defined!\n");
		}
		
		iface->target = $10;
		iface->target->default_route=iface;
		iface->target->default_route_mac=$8;
		
		printdbg("\tAdding target with default link '%s'\n", $6);
		add_target($10);
	}
	;

rule: 	{
		$$ = (struct target *)g_malloc0(sizeof(struct target));
		$$->back_handlers = g_tree_new_full((GCompareDataFunc) intcmp,
                    NULL, g_free, (GDestroyNotify) free_handler);
        $$->intra_handlers = g_tree_new_full((GCompareDataFunc) intcmp,
                    NULL, g_free, NULL);		
	}
	| rule FRONTEND QUOTE WORD QUOTE honeynet mac netmask vlan SEMICOLON {
		$$->front_handler = g_malloc0(sizeof(struct handler));
		$$->front_handler->iface = g_hash_table_lookup(links, $4);
		
		if($$->front_handler->iface == NULL) {
			yyerror("Front handler interface is undefined!\n");
		}
		
		$$->front_handler->ip=$6;
		$$->front_handler->mac=$7;
		$$->front_handler->netmask = $8;
        $$->front_handler->vlan.i = htons($9 & ((1 << 12)-1));
        
        $$->front_handler->ip_str=g_strdup(addr_ntoa($6));
		
        char *mac = g_strdup(addr_ntoa($$->front_handler->mac));
               
		g_printerr("\tFrontend defined at %s hw %s VLAN %u on '%s'\n", 
			addr_ntoa($6), mac, $9, $4);
			
		g_free($4);	
		free(mac);
	}
	| rule FRONTEND QUOTE WORD QUOTE honeynet mac netmask vlan QUOTE equation QUOTE SEMICOLON {
	
		$$->front_handler = g_malloc0(sizeof(struct handler));
		$$->front_handler->iface = g_hash_table_lookup(links, $4);
		
		if($$->front_handler->iface == NULL) {
			yyerror("Front handler interface is undefined!\n");
		}
		
		$$->front_handler->ip=$6;
		$$->front_handler->mac=$7;
		$$->front_handler->netmask = $8;
        $$->front_handler->vlan.i = htons($9 & ((1 << 12)-1));
		$$->front_handler->rule = DE_create_tree($11->str);
		
		$$->front_handler->ip_str=g_strdup(addr_ntoa($6));
		
        char *mac = g_strdup(addr_ntoa($$->front_handler->mac));
                
		g_printerr("\tFrontend defined at %s hw %s VLAN %u on '%s' with rule: %s\n", 
			$$->front_handler->ip_str, mac, $9, $4, $11->str);
			
		g_free($4);
		g_string_free($11, TRUE);
		free(mac);
	}
	| rule BACKPICK QUOTE equation QUOTE SEMICOLON {
        g_printerr("\tCreating backend picking rule: %s\n", $4->str);
		$$->back_picker = DE_create_tree($4->str);
		g_string_free($4, TRUE);
    }
	| rule BACKEND QUOTE WORD QUOTE honeynet mac netmask vlan SEMICOLON {
    	if($$->back_picker == NULL) {
    		yyerror("Backend needs a rule if no backend picking rule is defined!\n");
    	}
    		
    	struct interface *iface = g_hash_table_lookup(links, $4);
    	if(iface == NULL) {
    		yyerror("Back handler interface is undefined!\n");
    	}	
    		
    	// This will be freed automatically when the tree is destroyed
    	$$->back_handler_count++;
    	uint64_t *key=malloc(sizeof(uint64_t));
    	*key=$$->back_handler_count;
    		
    	struct handler *back_handler = g_malloc0(sizeof(struct handler));
    	back_handler->iface=iface;
    
        back_handler->ip=$6;
       	back_handler->mac=$7;
       	back_handler->netmask = $8;
       	back_handler->vlan.i = htons($9 & ((1 << 12)-1));    	
       	
       	back_handler->ip_str=g_strdup(addr_ntoa($6));
       	    
    	g_tree_insert($$->back_handlers, key, back_handler);
    		
        char *mac = g_strdup(addr_ntoa(back_handler->mac));
        
    	g_printerr("\tBackend #%lu defined at %s hw %s VLAN %u on '%s' copied to handler without a rule\n",
    		*key, addr_ntoa($6), mac, $9, $4);
    		
    	g_free($4);
    	free(mac);
    }
	| rule BACKEND QUOTE WORD QUOTE honeynet mac netmask vlan QUOTE equation QUOTE SEMICOLON {

		struct interface *iface = g_hash_table_lookup(links, $4);
    	if(iface == NULL) {
    		yyerror("Back handler interface is undefined!\n");
    	}
    	
    	// This will be freed automatically when the tree is destroyed
        $$->back_handler_count++;
        uint64_t *key=malloc(sizeof(uint64_t));
        *key=$$->back_handler_count;
            
        struct handler *back_handler = g_malloc0(sizeof(struct handler));
        back_handler->iface=g_hash_table_lookup(links, $4);
    
        back_handler->ip=$6;
       	back_handler->mac=$7;
       	back_handler->netmask = $8;
       	back_handler->vlan.i = htons($9 & ((1 << 12)-1));  
        back_handler->rule=DE_create_tree($11->str);
        
        back_handler->ip_str=g_strdup(addr_ntoa($6));
    
    	g_tree_insert($$->back_handlers, key, back_handler);
        
        char *mac = g_strdup(addr_ntoa(back_handler->mac));
        
        g_printerr("\tBackend #%lu defined at %s hw %s VLAN %u on '%s' with rule: %s\n", *key, back_handler->ip_str,
        	mac, $9, $4, $11->str);
                
        g_string_free($11, TRUE);
        g_free($4);
        free(mac);
    }
	| rule INTERNAL QUOTE WORD QUOTE honeynet WITH honeynet mac netmask vlan SEMICOLON {
    		
    	struct interface *iface = g_hash_table_lookup(links, $4);
    	if(iface == NULL) {
    		yyerror("Intra handler interface is undefined!\n");
    	}	
    		
    	struct handler *intra_handler = g_malloc0(sizeof(struct handler));
    	intra_handler->iface=iface;
        intra_handler->ip=$8;
       	intra_handler->mac=$9;
       	intra_handler->netmask = $10;
       	intra_handler->vlan.i = htons($11 & ((1 << 12)-1));
       	intra_handler->exclusive = 1;  	
       	intra_handler->ip_str=g_strdup(addr_ntoa($8));
       	    
        add_intra_handler($$, $6, intra_handler);

        char *mac = g_strdup(addr_ntoa(intra_handler->mac));
        char *intra_ip_str = g_strdup(addr_ntoa($6));    
        
    	g_printerr("\tInternal target for %s defined at %s hw %s VLAN %u on '%s'\n",
    		intra_ip_str, intra_handler->ip_str, mac, $11, $4);
    		
    	g_free($4);
    	free(mac);
    	free(intra_ip_str);
    }
	| rule INTERNAL QUOTE WORD QUOTE honeynet WITH honeynet mac netmask vlan QUOTE equation QUOTE SEMICOLON {

		struct interface *iface = g_hash_table_lookup(links, $4);
    	if(iface == NULL) {
    		yyerror("Intra handler interface is undefined!\n");
    	}
            
        struct handler *intra_handler = g_malloc0(sizeof(struct handler));
        intra_handler->iface=g_hash_table_lookup(links, $4);
        intra_handler->ip=$8;
       	intra_handler->mac=$9;
       	intra_handler->netmask = $10;
       	intra_handler->vlan.i = htons($11 & ((1 << 12)-1));  
        intra_handler->rule=DE_create_tree($13->str);
        intra_handler->exclusive = 1;
        intra_handler->ip_str=g_strdup(addr_ntoa($8));
    
        add_intra_handler($$, $6, intra_handler);
    
        char *mac = g_strdup(addr_ntoa(intra_handler->mac));
        char *intra_ip_str = g_strdup(addr_ntoa($6));
        
        g_printerr("\tInternal target for %s defined at %s hw %s VLAN %u on '%s' with rule: %s\n", 
        	intra_ip_str, intra_handler->ip_str,
        	mac, $11, $4, $13->str);
                
        g_string_free($13, TRUE);
        g_free($4);
        free(mac);
        free(intra_ip_str);
        
    }
	| rule INTERNET QUOTE equation QUOTE SEMICOLON {
		g_printerr("\tControl rule defined as: %s\n", $4->str);
		$$->control_rule = DE_create_tree($4->str);
		g_string_free($4, TRUE);
	}
	
    | rule INTRALAN QUOTE equation QUOTE SEMICOLON {
        g_printerr("\tControl rule defined as: %s\n", $4->str);
        $$->intra_rule = DE_create_tree($4->str);
        g_string_free($4, TRUE);
    }
	;

honeynet: EXPR {
        $$ = (struct addr *)g_malloc0(sizeof(struct addr));
		if (addr_pton($1, $$) < 0) {
            yyerror("\tIllegal IP address");
        }
        g_free($1);
	}
	
mac: HW EXPR {
		$$ = (struct addr *)g_malloc0(sizeof(struct addr));
		if (addr_pton($2, $$) < 0) {
            yyerror("\tIllegal MAC address");
        }
        g_free($2);
	}
	;
	
netmask: {
		$$ = NULL;
	}
	| netmask NETMASK EXPR {
		$$ = (struct addr *)g_malloc0(sizeof(struct addr));
		if (addr_pton($3, $$) < 0) {
            yyerror("\tIllegal IP address");
        }
        g_free($3);
	}
	;
	
vlan: {
		$$ = 0;
	}
	| vlan VLAN NUMBER {
		$$ = $3;
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

