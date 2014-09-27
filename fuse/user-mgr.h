#ifndef USER_MGR_H
#define USER_MGR_H

#include <glib.h>
#include <ccnet/ccnet-object.h>
#include <seaf-db.h>

typedef struct SeafUserManager {
    char                *ccnet_dir;
    GKeyFile            *keyf;
    SeafDB              *ccnetdb;

#ifdef HAVE_LDAP
    gboolean        use_ldap;
    char           *ldap_host;
#ifdef WIN32
    gboolean        use_ssl;
#endif
    char           **base_list;  /* base DN from where all users can be reached */
    char           *filter;     /* Additional search filter */
    char           *user_dn;    /* DN of the admin user */
    char           *password;   /* password for admin user */
    char           *login_attr;  /* attribute name used for login */
#endif
} SeafUserManager;

SeafUserManager*
seaf_user_manager_new (char *ccnet_dir);

void
seaf_user_manager_delete (SeafUserManager *user_mgr);

GList*
seaf_user_manager_get_emailusers (SeafUserManager *manager,
                                  const char *source,
                                  int start, int limit);
CcnetEmailUser*
seaf_user_manager_get_emailuser (SeafUserManager *manager,
                                 const char *email);
#endif

