/* The multiplexer helper lets you split the calling chain depending
   on the calling mode (get vs getnext vs set).  Useful if you want
   different routines to handle different aspects of SNMP requests,
   which is very common for GET vs SET type actions.

   Functionally:

   1) GET requests call the get_method
   2) GETNEXT requests call the getnext_method, or if not present, the
      get_method.
   3) GETBULK requests call the getbulk_method, or if not present, the
      getnext_method, or if even that isn't present the get_method.
   4) SET requests call the set_method, or if not present return a
      SNMP_ERR_NOTWRITABLE error.

 */

typedef struct mib_handler_methods_s {
   mib_handler *get_handler;
   mib_handler *getnext_handler;
   mib_handler *getbulk_handler;
   mib_handler *set_handler;
} mib_handler_methods;

mib_handler *get_multiplexer_handler(mib_handler_methods *);

NodeHandler multiplexer_helper_handler;

