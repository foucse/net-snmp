/* The serialized helper merely calls its clients multiple times for a
 * given request set, so they don't have to loop through the requests
 * themselves.
 */

mib_handler *get_serialize_handler(void);
int register_serialize(handler_registration *reginfo);

NodeHandler serialize_helper_handler;

