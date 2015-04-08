/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x501
#endif

#include <windows.h>
#include <AccCtrl.h>
#include <AclApi.h>
#include <stdio.h>

#include "utils.h"
#include "log.h"

enum SeafPathPerm {
    SEAF_PATH_PERM_RO = 0,
    SEAF_PATH_PERM_RW,
};
typedef enum SeafPathPerm SeafPathPerm;

#define WIN32_WRITE_ACCESS_MASK (FILE_WRITE_DATA | FILE_ADD_FILE | FILE_APPEND_DATA | \
                                 FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | \
                                 FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES | \
                                 DELETE)

// Remove explicit ACEs set by us.
static int
unset_permissions (PACL dacl)
{
    ACL_SIZE_INFORMATION size_info;

    if (!GetAclInformation (dacl, &size_info,
                            sizeof(size_info), AclSizeInformation)) {
        seaf_warning ("GetAclInformation Error: %u\n", GetLastError());
        return -1;
    }

    DWORD i;
    ACE_HEADER *ace;
    ACCESS_DENIED_ACE *deny_ace;
    ACCESS_ALLOWED_ACE *allowed_ace;
    for (i = 0; i < size_info.AceCount; ++i) {
        if (!GetAce(dacl, i, (void**)&ace)) {
            seaf_warning ("GetAce Error: %u\n", GetLastError());
            return -1;
        }

        // Skip inherited ACEs.
        if (ace->AceFlags & INHERITED_ACE)
            continue;

        if (ace->AceType == ACCESS_DENIED_ACE_TYPE) {
            deny_ace = (ACCESS_DENIED_ACE *)ace;
            if (deny_ace->Mask == WIN32_WRITE_ACCESS_MASK) {
                DeleteAce(dacl, i);
                break;
            }
        } else if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            allowed_ace = (ACCESS_ALLOWED_ACE *)ace;
            if (allowed_ace->Mask == WIN32_WRITE_ACCESS_MASK) {
                DeleteAce(dacl, i);
                break;
            }
        }
    }

    return 0;
}

static int
set_path_permission (const char *path, SeafPathPerm perm)
{
    wchar_t *wpath = NULL;
    int ret = 0;
    DWORD res = 0;
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    EXPLICIT_ACCESS ea;

    g_return_val_if_fail (perm == SEAF_PATH_PERM_RO || perm == SEAF_PATH_PERM_RW, -1);

    wpath = win32_long_path (path);
    if (!wpath)
        return -1;

    res = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, &old_dacl, NULL, &sd);
    if (ERROR_SUCCESS != res) {
        seaf_warning( "GetNamedSecurityInfo Error for path %s: %u\n", path, res );
        ret = -1;
        goto cleanup;
    }  

    unset_permissions (old_dacl);

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 

    memset (&ea, 0, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = WIN32_WRITE_ACCESS_MASK;
    ea.grfAccessMode = ((perm == SEAF_PATH_PERM_RO)?DENY_ACCESS:GRANT_ACCESS);
    ea.grfInheritance = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = "CURRENT_USER";

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    res = SetEntriesInAcl(1, &ea, old_dacl, &new_dacl);
    if (ERROR_SUCCESS != res)  {
        seaf_warning( "SetEntriesInAcl Error %u\n", res );
        ret = -1;
        goto cleanup;
    }  

    // Attach the new ACL as the object's DACL.

    res = SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, new_dacl, NULL);
    if (ERROR_SUCCESS != res)  {
        seaf_warning( "SetNamedSecurityInfo Error %u\n", res );
        ret = -1;
        goto cleanup;
    }

 cleanup:
    g_free (wpath);
    if(sd != NULL) 
        LocalFree((HLOCAL) sd);
    if(new_dacl != NULL) 
        LocalFree((HLOCAL) new_dacl);
    return ret;
}

static int
unset_path_permission (const char *path)
{
    wchar_t *wpath = NULL;
    int ret = 0;
    DWORD res = 0;
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;

    wpath = win32_long_path (path);
    if (!wpath)
        return -1;

    res = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, &old_dacl, NULL, &sd);
    if (ERROR_SUCCESS != res) {
        seaf_warning( "GetNamedSecurityInfo Error %u\n", res );
        ret = -1;
        goto cleanup;
    }  

    // Create a new copy of the old ACL

    res = SetEntriesInAcl(0, NULL, old_dacl, &new_dacl);
    if (ERROR_SUCCESS != res)  {
        seaf_warning( "SetEntriesInAcl Error %u\n", res );
        ret = -1;
        goto cleanup;
    }  

    unset_permissions (new_dacl);

    // Update path's ACL

    res = SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, new_dacl, NULL);
    if (ERROR_SUCCESS != res)  {
        seaf_warning( "SetNamedSecurityInfo Error %u\n", res );
        ret = -1;
        goto cleanup;
    }

 cleanup:
    g_free (wpath);
    if(sd != NULL) 
        LocalFree((HLOCAL) sd);
    if(new_dacl != NULL) 
        LocalFree((HLOCAL) new_dacl);
    return ret;
}

static char **
get_argv_utf8 (int *argc)
{
    int i = 0;
    char **argv = NULL;
    const wchar_t *cmdline = NULL;
    wchar_t **argv_w = NULL;

    cmdline = GetCommandLineW();
    argv_w = CommandLineToArgvW (cmdline, argc); 
    if (!argv_w) {
        printf("failed to CommandLineToArgvW(), GLE=%lu\n", GetLastError());
        return NULL;
    }

    argv = (char **)malloc (sizeof(char*) * (*argc));
    for (i = 0; i < *argc; i++) {
        argv[i] = wchar_to_utf8 (argv_w[i]);
    }

    return argv;
}

int main (int argc, char **argv)
{
    argv = get_argv_utf8 (&argc);

    if (argc != 3) {
        printf ("usage: set-perm [-r|-w|-u] path\n");
        exit(1);
    }

    if (strcmp(argv[1], "-r") == 0)
        return set_path_permission (argv[2], SEAF_PATH_PERM_RO);
    else if (strcmp (argv[1], "-w") == 0)
        return set_path_permission (argv[2], SEAF_PATH_PERM_RW);
    else if (strcmp (argv[1], "-u") == 0)
        return unset_path_permission (argv[2]);

    return 0;
}
