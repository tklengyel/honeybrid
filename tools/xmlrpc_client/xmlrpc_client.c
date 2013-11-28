/* A simple synchronous XML-RPC client program written in C, as an example of
   an Xmlrpc-c client.  This invokes the sample.add procedure that the
   Xmlrpc-c example xmlrpc_sample_add_server.c server provides.  I.e. it adds
   two numbers together, the hard way.

   This sends the RPC to the server running on the local system ("localhost"),
   HTTP Port 8080.
*/

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>


#define NAME "Xmlrpc-c Test Client"
#define VERSION "1.0"

static void 
dieIfFaultOccurred (xmlrpc_env * const envP) {
    if (envP->fault_occurred) {
        fprintf(stderr, "ERROR: %s (%d)\n",
                envP->fault_string, envP->fault_code);
        exit(1);
    }
}

int 
main(int           const argc, 
     const char ** const argv) {

    xmlrpc_env env;
    xmlrpc_value * resultP;
    xmlrpc_int32 number_of_links;
    const char * const serverUrl = "http://localhost:4567/RPC2";
    const char * const methodName = "get_number_of_links";

    if (argc-1 > 0) {
        fprintf(stderr, "This program has no arguments\n");
        exit(1);
    }

    /* Initialize our error-handling environment. */
    xmlrpc_env_init(&env);

    /* Start up our XML-RPC client library. */
    xmlrpc_client_init2(&env, XMLRPC_CLIENT_NO_FLAGS, NAME, VERSION, NULL, 0);
    dieIfFaultOccurred(&env);

    printf("Making XMLRPC call to server url '%s' method '%s'\n", serverUrl, "get_number_of_links");

    /* Make the remote procedure call */
    resultP = xmlrpc_client_call(&env, serverUrl, "get_number_of_links",
                                 "(i)", (xmlrpc_int32) 1);
    dieIfFaultOccurred(&env);
    
    /* Get our sum and print it out. */
    xmlrpc_read_int(&env, resultP, &number_of_links);
    dieIfFaultOccurred(&env);
    printf("Number of links defined: %d\n", number_of_links);
    
    /* Dispose of our result value. */
    xmlrpc_DECREF(resultP);

    /* Make the remote procedure call */
    resultP = xmlrpc_client_call(&env, serverUrl, "get_links",
                                 "(i)", (xmlrpc_int32) 1);
    dieIfFaultOccurred(&env);

    int array_size =xmlrpc_array_size(&env, resultP);
    while(array_size>0) {
    	--array_size;
    	xmlrpc_value *value;
    	const char *link;
    	xmlrpc_array_read_item(&env, resultP, 0, &value);
    	xmlrpc_read_string(&env, value, &link);
    	printf("Link %u: %s\n", array_size, link);
    	xmlrpc_DECREF(value);
    }
    xmlrpc_DECREF(resultP);

	/* Make the remote procedure call */
	resultP = xmlrpc_client_call(&env, serverUrl, "add_target", "(i)",
			(xmlrpc_int32) 1);

	xmlrpc_int64 targetID = 0;
    xmlrpc_read_i8(&env, resultP, &targetID);

    if(targetID) {
    	printf("New target added with ID: %"PRIx64"\n", targetID);
    } else {
    	printf("Failed to add new target!\n");
    	goto done;
    }
    xmlrpc_DECREF(resultP);

	/* Make the remote procedure call */
	resultP = xmlrpc_client_call(&env, serverUrl, "remove_target", "(i)",
			(xmlrpc_int64) targetID);

	xmlrpc_int32 res;
    xmlrpc_read_int(&env, resultP, &res);
    printf("Target %"PRIx64" remove: %"PRIx32"\n", targetID, res);

    done:
    xmlrpc_DECREF(resultP);

    /* Clean up our error-handling environment. */
    xmlrpc_env_clean(&env);
    
    /* Shutdown our XML-RPC client library. */
    xmlrpc_client_cleanup();

    return 0;
}

