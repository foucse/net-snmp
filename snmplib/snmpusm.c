/* snmpusm.c: routines to manipulate a information about a "user" as
   defined by the SNMP-USER-BASED-SM-MIB mib */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "asn1.h"
#include "snmpv3.h"
#include "snmpusm.h"

/* usm_get_user(): Returns a user from userList based on the engineID,
   engineIDLen and name of the requested user. */
   
struct usmUser *usm_get_user(char *engineID, int engineIDLen, char *name,
                         struct usmUser *userList) {
  struct usmUser *ptr;
  for (ptr = userList; ptr != NULL; ptr = ptr->next) {
    if (ptr->engineIDLen == engineIDLen &&
        memcmp(ptr->engineID, engineID, engineIDLen) == 0 &&
        strcmp(ptr->name, name))
      return ptr;
  }
  return NULL;
}

/* usm_add_user(): Add's a user to the userList, sorted by the
   engineIDLength then the engineID then the name length then the name
   to facilitate getNext calls on a usmUser table which is indexed by
   these values.

   Note: userList must not be NULL (obviously), as thats a rather trivial
   addition and is left to the API user.

   returns the head of the list (which could change due to this add).
*/

struct usmUser *usm_add_user(struct usmUser *user, struct usmUser *userList) {
  struct usmUser *nptr, *pptr;

  /* loop through userList till we find the proper, sorted place to
     insert the new user */
  for (nptr = userList, pptr = NULL; nptr != NULL;
       pptr = nptr, nptr = nptr->next) {
    if (nptr->engineIDLen > user->engineIDLen)
      continue;

    if (nptr->engineIDLen == user->engineIDLen &&
        memcmp(nptr->engineID, user->engineID, user->engineIDLen) > 0)
      continue;
    
    if (nptr->engineIDLen == user->engineIDLen &&
        memcmp(nptr->engineID, user->engineID, user->engineIDLen) == 0 &&
        strlen(nptr->name) > strlen(user->name))
      continue;

    if (nptr->engineIDLen == user->engineIDLen &&
        memcmp(nptr->engineID, user->engineID, user->engineIDLen) == 0 &&
        strlen(nptr->name) == strlen(user->name) &&
        strcmp(nptr->name, pptr->name) > 0)
      continue;
  }

  /* nptr should now point to the user that we need to add ourselves
     in front of, and pptr should be our new 'prev'. */

  /* change our pointers */
  user->prev = pptr;
  user->next = nptr;

  /* change the next's prev pointer */
  user->next->prev = user;

  /* change the prev's next pointer */
  user->prev->next = user;
  
  /* rewind to the head of the list and return it (since the new head
     could be us, we need to notify the above routine who the head now is. */
  for(pptr = user; pptr->prev != NULL; pptr = pptr->prev);
  return pptr;
}

/* usm_free_user():  calls free() on all needed parts of struct usmUser and
   the user himself.

   Note: This should *not* be called on an object in a list (IE,
   remove it from the list first, and set next and prev to NULL), but
   will try to reconnect the list pieces again if it is called this
   way.  If called on the head of the list, the entire list will be
   lost. */
struct usmUser *usm_free_user(struct usmUser *user) {
  if (user->engineID != NULL)
    free(user->engineID);
  if (user->name != NULL)
    free(user->name);
  if (user->secName != NULL)
    free(user->secName);
  if (user->cloneFrom != NULL)
    free(user->cloneFrom);
  if (user->authProtocol != NULL)
    free(user->authProtocol);
  if (user->authKey != NULL)
    free(user->authKey);
  if (user->privProtocol != NULL)
    free(user->privProtocol);
  if (user->privKey != NULL)
    free(user->privKey);
  if (user->userPublicString != NULL)
    free(user->userPublicString);
  if (user->prev != NULL) { /* ack, this shouldn't happen */
    user->prev->next = user->next;
  }
  if (user->next != NULL) { 
    user->next->prev = user->prev;
    if (user->prev != NULL) /* ack this is really bad, because it means
                              we'll loose the head of some structure tree */
      DEBUGP("Severe: Asked to free the head of a usmUser tree somewhere.");
  }
  return NULL;  /* for convenience to returns from calling functions */
}

/* take a given user and duplicate him */
struct usmUser *usm_clone_user(struct usmUser *from) {
  struct usmUser *ptr;
  struct usmUser *newUser;

  /* create the new user */
  newUser = (struct usmUser *) malloc(sizeof(struct usmUser));
  if (newUser == NULL)
    return NULL;
  memset(newUser, 0, sizeof(struct usmUser));  /* initialize everything to 0 */
  
/* leave everything un-initialized if they didn't give us a user to
   clone from */
  if (from == NULL)
    return; 
  
  /* copy the engineID & it's length */
  if (from->engineIDLen > 0) {
    if ((newUser->engineID = (char *) malloc(from->engineIDLen*sizeof(char)))
        == NULL);
      return usm_free_user(newUser);
    newUser->engineIDLen = from->engineIDLen;
    memcpy(newUser->engineID, from->engineID, from->engineIDLen*sizeof(char));
  }
  
  /* copy the name of the user */
  if (from->name != NULL)
    if ((newUser->name = strdup(from->name)) == NULL)
      return usm_free_user(newUser);

  /* copy the security Name for the user */
  if (from->secName != NULL)
    if ((newUser->secName = strdup(from->secName)) == NULL)
      return usm_free_user(newUser);

  /* copy the cloneFrom oid row pointer */
  if (from->cloneFromLen > 0) {
    if ((newUser->cloneFrom = (oid *) malloc(sizeof(oid)*from->cloneFromLen))
        == NULL)
      return usm_free_user(newUser);
    memcpy(newUser->cloneFrom, from->cloneFrom,
           sizeof(oid)*from->cloneFromLen);
  }

  /* copy the authProtocol oid row pointer */
  if (from->authProtocolLen > 0) {
    if ((newUser->authProtocol =
         (oid *) malloc(sizeof(oid) * from->authProtocolLen)) == NULL)
      return usm_free_user(newUser);
    memcpy(newUser->authProtocol, from->authProtocol,
           sizeof(oid)*from->authProtocolLen);
  }

  /* copy the authKey */
  if (from->authKeyLen > 0) {
    if ((newUser->authKey = (char *) malloc(sizeof(char) * from->authKeyLen))
        == NULL)
      return usm_free_user(newUser);
  }
  
  /* copy the privProtocol oid row pointer */
  if (from->privProtocolLen > 0) {
    if ((newUser->privProtocol =
         (oid *) malloc(sizeof(oid)*from->privProtocolLen)) == NULL)
      return usm_free_user(newUser);
    memcpy(newUser->privProtocol, from->privProtocol,
           sizeof(oid)*from->privProtocolLen);
  }
  
  /* copy the privKey */
  if (from->privKeyLen > 0) {
    if ((newUser->privKey = (char *) malloc(sizeof(char) * from->privKeyLen))
        == NULL)
      return usm_free_user(newUser);
  }

  /* copy the userPublicString convenience string */
  if (from->userPublicString != NULL)
    if ((newUser->userPublicString = strdup(from->userPublicString)) == NULL)
      return usm_free_user(newUser);

  return newUser;
}

/* create_initial_user: creates an initial user, filled with the
   defaults defined in the USM document. */

static oid usmDESPrivProtocol[] = { 1,3,6,1,6,3,10,1,2,2 };
static oid usmHMACMD5AuthProtocol[] = { 1,3,6,1,6,3,10,1,2,2 };
  
struct usmUser *usm_create_initial_user(void) {
  struct usmUser *newUser  = usm_clone_user(NULL);

  if ((newUser->name = strdup("initial")) == NULL)
    return usm_free_user(newUser);

  if ((newUser->secName = strdup("initial")) == NULL)
    return usm_free_user(newUser);

  if ((newUser->engineID = snmpv3_generate_engineID(&newUser->engineIDLen))
      == NULL)
    return usm_free_user(newUser);

  if ((newUser->cloneFrom = (oid *) malloc(sizeof(oid)*2)) == NULL)
    return usm_free_user(newUser);
  newUser->cloneFrom[0] = 0;
  newUser->cloneFrom[1] = 0;

  if ((newUser->privProtocol = (oid *) malloc(sizeof(usmDESPrivProtocol)))
      == NULL)
    return usm_free_user(newUser);
  newUser->privProtocolLen = sizeof(usmDESPrivProtocol)/sizeof(oid);
  memcpy(newUser->privProtocol, usmDESPrivProtocol, sizeof(usmDESPrivProtocol));

  if ((newUser->authProtocol = (oid *) malloc(sizeof(usmHMACMD5AuthProtocol)))
      == NULL)
    return usm_free_user(newUser);
  newUser->authProtocolLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
  memcpy(newUser->authProtocol, usmHMACMD5AuthProtocol,
         sizeof(usmHMACMD5AuthProtocol));
  
  return newUser;
}

