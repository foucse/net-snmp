/* testhandler.h */

/* The instance helper is designed to simplify the task of adding simple
 * instances to the mib tree.
 */

/* GETNEXTs are auto-converted to a GET.
 * non-valid GETs are dropped.
 * The client can assume that if you're called for a GET, it shouldn't
 * have to check the oid at all.  Just answer.
 */

int register_instance(handler_registration *reginfo);
mib_handler *get_instance_handler(void);
   
NodeHandler instance_helper_handler;

