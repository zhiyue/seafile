#ifndef USER_MGR_H
#define USER_MGR_H

#include <glib.h>
#include <ccnet/ccnet-object.h>
#include <seaf-db.h>

typedef struct FuseUserManager {
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
} FuseUserManager;

FuseUserManager*
fuse_user_manager_new (char *ccnet_dir);

void
fuse_user_manager_delete (FuseUserManager *user_mgr);

GList*
fuse_user_manager_get_emailusers (FuseUserManager *manager,
                                  const char *source,
                                  int start, int limit);
CcnetEmailUser*
fuse_user_manager_get_emailuser (FuseUserManager *manager,
                                 const char *email);
#endif

