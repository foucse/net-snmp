/* snmpusm.h: header file for usm support */
#ifndef SNMPUSM_H
#define SNMPUSM_H

/* struct usmUser: a structure to represent a given user in a list */
struct usmUser;
struct usmUser {
   u_char         *engineID;
   int            engineIDLen;
   u_char         *name;
   u_char         *secName;
   oid            *cloneFrom;
   int            cloneFromLen;
   oid            *authProtocol;
   int            authProtocolLen;
   u_char         *authKey;
   int            authKeyLen;
   oid            *privProtocol;
   int            privProtocolLen;
   u_char         *privKey;
   int            privKeyLen;
   u_char         *userPublicString;
   struct usmUser *next;
   struct usmUser *prev;
};

/* functions defined in the sister .h file */
struct usmUser *usm_get_user(char *engineID, int engineIDLen, char *name,
                         struct usmUser *userList);
struct usmUser *usm_add_user(struct usmUser *user, struct usmUser *userList);
struct usmUser *usm_free_user(struct usmUser *user);
struct usmUser *usm_clone_user(struct usmUser *from);
struct usmUser *usm_create_initial_user();

#endif /* SNMPUSM_H */
