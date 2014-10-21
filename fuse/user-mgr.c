#include <sys/stat.h>
#include <string.h>
#include <glib/gstdio.h>
#include "ccnetdb-config.h"

#ifdef HAVE_LDAP
  #ifndef WIN32
    #define LDAP_DEPRECATED 1
    #include <ldap.h>
  #else
    #include <winldap.h>
  #endif
#endif

FuseUserManager*
fuse_user_manager_new (char *ccnet_dir)
{
    char *ccnet_file_path;
    struct stat st;
    GError *error;
    GKeyFile *ccnet_config;

    if (g_stat(ccnet_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        g_warning ("ccnet dir %s does not exist and is unable to create.\n",
                   ccnet_dir);
        g_free (ccnet_dir);
        return NULL;
    }

    ccnet_file_path = g_build_filename (ccnet_dir, "ccnet.conf", NULL);
    ccnet_config = g_key_file_new ();
    if (!g_key_file_load_from_file (ccnet_config, ccnet_file_path,
                                    G_KEY_FILE_NONE, &error)) {
        g_warning ("Failed to load ccnet config file: %s.\n", error->message);
        g_key_file_free (ccnet_config);
        g_free (ccnet_dir);
        g_free (ccnet_file_path);
        g_clear_error (&error);
        return NULL;
    }

    FuseUserManager *mgr = g_new0 (FuseUserManager, 1);
    mgr->ccnet_dir = ccnet_dir;
    mgr->keyf = ccnet_config;

#ifdef HAVE_LDAP
    if (load_ldap_settings (mgr) < 0) {
        g_warning ("Failed to load ldap setting.\n");
        goto out;
    }
#endif

    if (load_ccnetdb_config (mgr) < 0) {
        g_warning ("Failed to load ccnet db config.\n");
        goto out;
    }

    return mgr;

out:
    fuse_user_manager_delete (mgr);
    return NULL;
}

void
fuse_user_manager_delete (FuseUserManager *user_mgr)
{
    if (!user_mgr)
        return;

    if (user_mgr->ccnet_dir)
        g_free (user_mgr->ccnet_dir);

    if (user_mgr->keyf)
        g_key_file_free (user_mgr->keyf);

#ifdef HAVE_LDAP
    if (user_mgr->use_ldap) {
        if (user_mgr->ldap_host)
            g_free (user_mgr->ldap_host);

        if (user_mgr->base_list)
            g_strfreev (base_list);

        if (user_mgr->filter)
            g_free (user_mgr->filter);

        if (user_mgr->user_dn)
            g_free (user_mgr->user_dn);

        if (user_mgr->password)
            g_free (user_mgr->password);

        if (user_mgr->login_attr)
            g_free (user_mgr->login_attr);
    }
#endif

    if (user_mgr->ccnetdb)
       seaf_db_free (user_mgr->ccnetdb);

    g_free (user_mgr);
}

#ifdef HAVE_LDAP
static LDAP *ldap_init_and_bind (const char *host,
#ifdef WIN32
                                 gboolean use_ssl,
#endif
                                 const char *user_dn,
                                 const char *password)
{
    LDAP *ld;
    int res;
    int desired_version = LDAP_VERSION3;

#ifndef WIN32
    res = ldap_initialize (&ld, host);
    if (res != LDAP_SUCCESS) {
        g_warning ("ldap_initialize failed: %s.\n", ldap_err2string(res));
        return NULL;
    }
#else
    char *host_copy = g_strdup (host);
    if (!use_ssl)
        ld = ldap_init (host_copy, LDAP_PORT);
    else
        ld = ldap_sslinit (host_copy, LDAP_SSL_PORT, 1);
    g_free (host_copy);
    if (!ld) {
        g_warning ("ldap_init failed: %ul.\n", LdapGetLastError());
        return NULL;
    }
#endif

    /* set the LDAP version to be 3 */
    res = ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version);
    if (res != LDAP_OPT_SUCCESS) {
        g_warning ("ldap_set_option failed: %s.\n", ldap_err2string(res));
        return NULL;
    }

    if (user_dn) {
#ifndef WIN32
        res = ldap_bind_s (ld, user_dn, password, LDAP_AUTH_SIMPLE);
#else
        char *dn_copy = g_strdup(user_dn);
        char *password_copy = g_strdup(password);
        res = ldap_bind_s (ld, dn_copy, password_copy, LDAP_AUTH_SIMPLE);
        g_free (dn_copy);
        g_free (password_copy);
#endif
        if (res != LDAP_SUCCESS ) {
            g_warning ("ldap_bind failed: %s.\n", ldap_err2string(res));
            ldap_unbind_s (ld);
            return NULL;
        }
    }

    return ld;
}

static GList *ldap_list_users (FuseUserManager *manager, const char *uid,
                               int start, int limit)
{
    LDAP *ld = NULL;
    GList *ret = NULL;
    int res;
    GString *filter;
    char *filter_str;
    char *attrs[2];
    LDAPMessage *msg = NULL, *entry;

    ld = ldap_init_and_bind (manager->ldap_host,
#ifdef WIN32
                             manager->use_ssl,
#endif
                             manager->user_dn,
                             manager->password);
    if (!ld)
        return NULL;

    filter = g_string_new (NULL);
    if (!manager->filter)
        g_string_printf (filter, "(%s=%s)", manager->login_attr, uid);
    else
        g_string_printf (filter, "(&(%s=%s) (%s))",
                         manager->login_attr, uid, manager->filter);
    filter_str = g_string_free (filter, FALSE);

    attrs[0] = manager->login_attr;
    attrs[1] = NULL;

    int i = 0;
    if (start == -1)
        start = 0;

    char **base;
    for (base = manager->base_list; *base; ++base) {
        res = ldap_search_s (ld, *base, LDAP_SCOPE_SUBTREE,
                             filter_str, attrs, 0, &msg);
        if (res != LDAP_SUCCESS) {
            g_warning ("ldap_search failed: %s.\n", ldap_err2string(res));
            ret = NULL;
            ldap_msgfree (msg);
            goto out;
        }

        for (entry = ldap_first_entry (ld, msg);
             entry != NULL;
             entry = ldap_next_entry (ld, entry), ++i) {
            char *attr;
            char **vals;
            BerElement *ber;
            CcnetEmailUser *user;

            if (i < start)
                continue;
            if (limit >= 0 && i >= start + limit) {
                ldap_msgfree (msg);
                goto out;
            }

            attr = ldap_first_attribute (ld, entry, &ber);
            vals = ldap_get_values (ld, entry, attr);

            char *email_l = g_ascii_strdown (vals[0], -1);
            user = g_object_new (CCNET_TYPE_EMAIL_USER,
                                 "id", 0,
                                 "email", email_l,
                                 "is_staff", FALSE,
                                 "is_active", TRUE,
                                 "ctime", (gint64)0,
                                 "source", "LDAP",
                                 NULL);
            g_free (email_l);
            ret = g_list_prepend (ret, user);

            ldap_memfree (attr);
            ldap_value_free (vals);
            ber_free (ber, 0);
        }

        ldap_msgfree (msg);
    }

out:
    g_free (filter_str);
    if (ld) ldap_unbind_s (ld);
    return ret;
}
#endif

static gboolean
get_emailusers_cb (SeafDBRow *row, void *data)
{
    GList **plist = data;
    CcnetEmailUser *emailuser;

    int id = seaf_db_row_get_column_int (row, 0);
    const char *email = (const char *)seaf_db_row_get_column_text (row, 1);
    int is_staff = seaf_db_row_get_column_int (row, 2);
    int is_active = seaf_db_row_get_column_int (row, 3);
    gint64 ctime = seaf_db_row_get_column_int64 (row, 4);
    const char *role = (const char *)seaf_db_row_get_column_text (row, 5);

    char *email_l = g_ascii_strdown (email, -1);
    emailuser = g_object_new (CCNET_TYPE_EMAIL_USER,
                              "id", id,
                              "email", email_l,
                              "is_staff", is_staff,
                              "is_active", is_active,
                              "ctime", ctime,
                              "role", role ? role : "",
                              "source", "DB",
                              NULL);
    g_free (email_l);

    *plist = g_list_prepend (*plist, emailuser);

    return TRUE;
}

static gboolean
get_emailuser_cb (SeafDBRow *row, void *data)
{
    CcnetEmailUser **p_emailuser = data;

    int id = seaf_db_row_get_column_int (row, 0);
    const char *email = (const char *)seaf_db_row_get_column_text (row, 1);
    int is_staff = seaf_db_row_get_column_int (row, 2);
    int is_active = seaf_db_row_get_column_int (row, 3);
    gint64 ctime = seaf_db_row_get_column_int64 (row, 4);

    char *email_l = g_ascii_strdown (email, -1);
    *p_emailuser = g_object_new (CCNET_TYPE_EMAIL_USER,
                                 "id", id,
                                 "email", email_l,
                                 "is_staff", is_staff,
                                 "is_active", is_active,
                                 "ctime", ctime,
                                 "source", "DB",
                                 NULL);
    g_free (email_l);

    return FALSE;
}

GList*
fuse_user_manager_get_emailusers (FuseUserManager *manager,
                                  const char *source,
                                  int start, int limit)
{
    SeafDB *db = manager->ccnetdb;
    GList *ret = NULL;

#ifdef HAVE_LDAP
    if (manager->use_ldap && g_strcmp0 (source, "LDAP") == 0) {
        GList *users;
        users = ldap_list_users (manager, "*", start, limit);
        return g_list_reverse (users);
    }
#endif

    if (g_strcmp0 (source, "DB") != 0)
        return NULL;

    int rc;
    if (start == -1 && limit == -1)
        rc = seaf_db_statement_foreach_row (db,
                                            "SELECT t1.id, t1.email, "
                                            "t1.is_staff, t1.is_active, t1.ctime, "
                                            "t2.role FROM EmailUser AS t1 "
                                            "LEFT JOIN UserRole AS t2 "
                                            "ON t1.email = t2.email ",
                                             get_emailusers_cb, &ret,
                                             0);
    else
        rc = seaf_db_statement_foreach_row (db,
                                            "SELECT t1.id, t1.email, "
                                            "t1.is_staff, t1.is_active, t1.ctime, "
                                            "t2.role FROM EmailUser AS t1 "
                                            "LEFT JOIN UserRole AS t2 "
                                            "ON t1.email = t2.email "
                                            "ORDER BY t1.id LIMIT ? OFFSET ?",
                                            get_emailusers_cb, &ret,
                                            2, "int", limit, "int", start);

    if (rc < 0) {
        while (ret != NULL) {
            g_object_unref (ret->data);
            ret = g_list_delete_link (ret, ret);
        }
        return NULL;
    }

    return g_list_reverse (ret);
}

static gboolean
get_role_emailuser_cb (SeafDBRow *row, void *data)
{
    *((char **)data) = g_strdup (seaf_db_row_get_column_text (row, 0));

    return FALSE;
}

static char*
fuse_user_manager_get_role_emailuser (FuseUserManager *manager,
                                      const char* email)
{

    SeafDB *db = manager->ccnetdb;
    const char *sql;
    char* role;

    sql = "SELECT role FROM UserRole WHERE email=?";
    if (seaf_db_statement_foreach_row (db, sql, get_role_emailuser_cb, &role,
                                       1, "string", email) > 0)
        return role;

    return NULL;
}

CcnetEmailUser*
fuse_user_manager_get_emailuser (FuseUserManager *manager,
                                 const char *email)
{
    SeafDB *db = manager->ccnetdb;
    char *sql;
    CcnetEmailUser *emailuser = NULL;
    char *email_down;

    sql = "SELECT id, email, is_staff, is_active, ctime"
          " FROM EmailUser WHERE email=?";
    if (seaf_db_statement_foreach_row (db, sql, get_emailuser_cb, &emailuser,
                                        1, "string", email) > 0) {
        char *role = fuse_user_manager_get_role_emailuser (manager, email);
        if (role) {
            g_object_set (emailuser, "role", role, NULL);
            g_free (role);
        }
        return emailuser;
    }

    email_down = g_ascii_strdown (email, strlen(email));
    if (seaf_db_statement_foreach_row (db, sql, get_emailuser_cb, &emailuser,
                                        1, "string", email_down) > 0) {
        char *role = fuse_user_manager_get_role_emailuser(manager, email_down);
        if (role) {
            g_object_set (emailuser, "role", role, NULL);
            g_free (role);
        }
        g_free (email_down);
        return emailuser;
    }
    g_free (email_down);

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        GList *users, *ptr;

        users = ldap_list_users (manager, email, -1, -1);
        if (!users)
            return NULL;
        emailuser = users->data;

        /* Free all except the first user. */
        for (ptr = users->next; ptr; ptr = ptr->next)
            g_object_unref (ptr->data);
        g_list_free (users);

        char *role = ccnet_user_manager_get_role_emailuser(manager, email);
        if (role) {
            g_object_set (emailuser, "role", role, NULL);
            g_free (role);
        }
        return emailuser;
    }
#endif

    return NULL;
}
