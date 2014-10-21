#include <string.h>
#include "ccnetdb-config.h"

#define DEFAULT_MAX_CONNECTIONS 100
#define CCNET_DB "ccnet.db"

static int
init_sqlite_database (FuseUserManager *manager)
{
    char *db_path;
    int max_connections = 0;

    max_connections = g_key_file_get_integer (manager->keyf, "database", "max_connections", NULL);
    if (max_connections <= 0)
        max_connections = DEFAULT_MAX_CONNECTIONS;

    db_path = g_build_path ("/", manager->ccnet_dir, CCNET_DB, NULL);

    manager->ccnetdb =  seaf_db_new_sqlite (db_path, max_connections);
    if (!manager->ccnetdb) {
        g_warning ("Failed to open database.\n");
        g_free (db_path);
        return -1;
    }

    g_free (db_path);

    return 0;
}

#define MYSQL_DEFAULT_PORT "3306"

static int
init_mysql_database (FuseUserManager *manager)
{
    char *host, *port, *user, *passwd, *db, *unix_socket, *charset;
    int max_connections = 0;
    gboolean use_ssl = FALSE;

    host = g_key_file_get_string (manager->keyf, "Database", "HOST", NULL);
    if (!host) {
        g_warning ("DB host not set in config.\n");
        return -1;
    }

    port = g_key_file_get_string (manager->keyf, "Database", "PORT", NULL);
    if (!port) {
        port = g_strdup (MYSQL_DEFAULT_PORT);
    }

    user = g_key_file_get_string (manager->keyf, "Database", "USER", NULL);
    if (!user) {
        g_warning ("DB user not set in config.\n");
        g_free (host);
        g_free (port);
        return -1;
    }

    passwd = g_key_file_get_string (manager->keyf, "Database", "PASSWD", NULL);
    if (!passwd) {
        g_warning ("DB passwd not set in config.\n");
        g_free (host);
        g_free (port);
        g_free (user);
        return -1;
    }

    db = g_key_file_get_string (manager->keyf, "Database", "DB", NULL);
    if (!db) {
        g_warning ("DB name not set in config.\n");
        g_free (host);
        g_free (port);
        g_free (user);
        g_free (passwd);
        return -1;
    }

    unix_socket = g_key_file_get_string (manager->keyf, "Database", "UNIX_SOCKET", NULL);
    use_ssl = g_key_file_get_boolean (manager->keyf, "Database", "USE_SSL", NULL);
    charset = g_key_file_get_string (manager->keyf, "Database", "CONNECTION_CHARSET", NULL);
    max_connections = g_key_file_get_integer (manager->keyf, "Database", "MAX_CONNECTIONS", NULL);
    if (max_connections <= 0)
        max_connections = DEFAULT_MAX_CONNECTIONS;

    manager->ccnetdb = seaf_db_new_mysql (host, port, user, passwd, db,
                                          unix_socket, use_ssl, charset, max_connections);
    if (!manager->ccnetdb) {
        g_warning ("Failed to open database.\n");
        g_free (host);
        g_free (port);
        g_free (user);
        g_free (passwd);
        g_free (db);
        g_free (unix_socket);
        g_free (charset);
        return -1;
    }

    g_free (host);
    g_free (port);
    g_free (user);
    g_free (passwd);
    g_free (db);
    g_free (unix_socket);
    g_free (charset);

    return 0;
}

static int
init_pgsql_database (FuseUserManager *manager)
{
    char *host, *user, *passwd, *db, *unix_socket;

    host = g_key_file_get_string (manager->keyf, "Database", "HOST", NULL);
    if (!host) {
        g_warning ("DB host not set in config.\n");
        return -1;
    }

    user = g_key_file_get_string (manager->keyf, "Database", "USER", NULL);
    if (!user) {
        g_warning ("DB user not set in config.\n");
        g_free (host);
        return -1;
    }

    passwd = g_key_file_get_string (manager->keyf, "Database", "PASSWD", NULL);
    if (!passwd) {
        g_warning ("DB passwd not set in config.\n");
        g_free (host);
        g_free (user);
        return -1;
    }

    db = g_key_file_get_string (manager->keyf, "Database", "DB", NULL);
    if (!db) {
        g_warning ("DB name not set in config.\n");
        g_free (host);
        g_free (user);
        g_free (passwd);
        return -1;
    }

    unix_socket = g_key_file_get_string (manager->keyf, "Database", "UNIX_SOCKET", NULL);

    manager->ccnetdb = seaf_db_new_pgsql (host, user, passwd, db, unix_socket);
    if (!manager->ccnetdb) {
        g_warning ("Failed to open database.\n");
        g_free (host);
        g_free (user);
        g_free (passwd);
        g_free (db);
        g_free (unix_socket);
        return -1;
    }

    g_free (host);
    g_free (user);
    g_free (passwd);
    g_free (db);
    g_free (unix_socket);

    return 0;
}

int
load_ccnetdb_config (FuseUserManager *manager)
{
    int ret;
    char *engine;

    engine = g_key_file_get_string (manager->keyf, "Database", "ENGINE", NULL);
    if (!engine || strcasecmp (engine, "sqlite") == 0) {
        ret = init_sqlite_database (manager);
    } else if (strcasecmp (engine, "mysql") == 0) {
        ret = init_mysql_database (manager);
    } else if (strcasecmp (engine, "pgsql") == 0) {
        ret = init_pgsql_database (manager);
    } else {
        g_warning ("Unknown database type: %s.\n", engine);
        ret = -1;
    }

    g_free (engine);

    return ret;
}

#ifdef HAVE_LDAP
int
load_ldap_settings (FuseUserManager *manager)
{
    GKeyFile *config = manager->keyf;

    manager->ldap_host = g_key_file_get_string (config, "LDAP", "HOST", NULL);
    if (!manager->ldap_host)
        return 0;

    manager->use_ldap = TRUE;

#ifdef WIN32
    manager->use_ssl = g_key_file_get_boolean (config, "LDAP", "USE_SSL", NULL);
#endif

    char *base_list = g_key_file_get_string (config, "LDAP", "BASE", NULL);
    if (!base_list) {
        g_warning ("LDAP: BASE not found in config file.\n");
        return -1;
    }
    manager->base_list = g_strsplit (base_list, ";", -1);

    manager->filter = g_key_file_get_string (config, "LDAP", "FILTER", NULL);

    manager->user_dn = g_key_file_get_string (config, "LDAP", "USER_DN", NULL);
    if (manager->user_dn) {
        manager->password = g_key_file_get_string (config, "LDAP", "PASSWORD", NULL);
        if (!manager->password) {
            g_warning ("LDAP: PASSWORD not found in config file.\n");
            return -1;
        }
    }
    /* Use anonymous if user_dn is not set. */

    manager->login_attr = g_key_file_get_string (config, "LDAP", "LOGIN_ATTR", NULL);
    if (!manager->login_attr)
        manager->login_attr = g_strdup("mail");

    return 0;
}
#endif
