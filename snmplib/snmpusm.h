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
   int            userStatus;
   int            userStorageType;
   struct usmUser *next;
   struct usmUser *prev;
};

/* Note: Any changes made to this structure need to be reflected in
   the following functions: */

struct usmUser *usm_get_user(char *engineID, int engineIDLen, char *name,
                         struct usmUser *userList);
struct usmUser *usm_add_user(struct usmUser *user, struct usmUser *userList);
struct usmUser *usm_free_user(struct usmUser *user);
struct usmUser *usm_clone_user(struct usmUser *from);
struct usmUser *usm_create_initial_user();
struct usmUser *usm_cloneFrom_user(struct usmUser *from, struct usmUser *to);
struct usmUser *usm_remove_user(struct usmUser *user, struct usmUser *userList);

#endif /* SNMPUSM_H */
