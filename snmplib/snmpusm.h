/* snmpusm.h: header file for usm support */
#ifndef SNMPUSM_H
#define SNMPUSM_H

int usm_generate_out_msg __P((int, u_char *, int, int, int, u_char *,int,
			      u_char *, int, int, u_char *, int, void *,
			      u_char *, int *, u_char **, int *));

int usm_process_in_msg __P((int, int, u_char *, int, int, u_char *, int,
			    u_char *, int *, u_char *, int *, u_char **, int *,
			    int *, void **));

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

int             usm_check_secLevel(int level, struct usmUser *user);
struct usmUser *usm_get_user(char *engineID, int engineIDLen, char *name,
                         struct usmUser *userList);
struct usmUser *usm_add_user(struct usmUser *user, struct usmUser *userList);
struct usmUser *usm_free_user(struct usmUser *user);
struct usmUser *usm_clone_user(struct usmUser *from);
struct usmUser *usm_create_initial_user();
struct usmUser *usm_cloneFrom_user(struct usmUser *from, struct usmUser *to);
struct usmUser *usm_remove_user(struct usmUser *user, struct usmUser *userList);
char           *get_objid(char *line, oid **optr, int *len);
void            usm_save_user(struct usmUser *user, char *token, char *type);
struct usmUser *usm_read_user(char *line);

#endif /* SNMPUSM_H */
