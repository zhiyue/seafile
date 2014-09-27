#ifndef CCNETDB_UTIL
#define CCNETDB_UTIL

#include "user-mgr.h"

int load_ccnetdb_config (SeafUserManager *manager);

#ifdef HAVE_LDAP
int load_ldap_settings (SeafUserManager *manager);
#endif


#endif


