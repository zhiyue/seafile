#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x500
#endif

#include <windows.h>
#include <stdio.h>

#include "utils.h"

#define WIN32_WRITE_ACCESS_MASK (FILE_WRITE_DATA | FILE_ADD_FILE | FILE_APPEND_DATA | \
                                 FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | \
                                 FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES \
                                 DELETE)

static int
set_path_read_only (const char *path)
{
    wchar_t *wpath = NULL;
    int ret = 0;
    DWORD res = 0;
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    EXPLICIT_ACCESS ea;

    wpath = win32_long_path (path);
    if (!wpath)
        return -1;

    res = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, &old_dacl, NULL, &sd);
    if (ERROR_SUCCESS != res) {
        printf( "GetNamedSecurityInfo Error %u\n", res );
        ret = -1;
        goto cleanup;
    }  

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 

    memset (&ea, 0, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = WIN32_WRITE_ACCESS_MASK;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);
    ea.Trustee.TrusteeForm = TRUSTEEE_IS_SID;
    ea.Trustee.ptstrName = CURRENT_USER;

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    res = SetEntriesInAcl(1, &ea, old_dacl, &new_dacl);
    if (ERROR_SUCCESS != res)  {
        printf( "SetEntriesInAcl Error %u\n", res );
        ret = -1;
        goto cleanup;
    }  

    // Attach the new ACL as the object's DACL.

    res = SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, new_dacl, NULL);
    if (ERROR_SUCCESS != res)  {
        printf( "SetNamedSecurityInfo Error %u\n", res );
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
unset_path_read_only (const char *path)
{
    wchar_t *wpath = NULL;
    int ret = 0;
    DWORD res = 0;
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    ACL_SIZE_INFORMATION size_info;

    wpath = win32_long_path (path);
    if (!wpath)
        return -1;

    res = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, &old_dacl, NULL, &sd);
    if (ERROR_SUCCESS != res) {
        printf( "GetNamedSecurityInfo Error %u\n", res );
        ret = -1;
        goto cleanup;
    }  

    // Create a new copy of the old ACL

    res = SetEntriesInAcl(0, NULL, old_dacl, &new_dacl);
    if (ERROR_SUCCESS != res)  {
        printf( "SetEntriesInAcl Error %u\n", res );
        ret = -1;
        goto cleanup;
    }  

    // Remove access deny ACE added by us

    if (!GetAclInformation (new_dacl, &size_info,
                            sizeof(size_info), AclSizeInformation)) {
        printf ("GetAclInformation Error: %u\n", GetLastError());
        ret = -1;
        goto cleanup;
    }

    DWORD i;
    ACE_HEADER *ace;
    ACCESS_DENIED_ACE *deny_ace;
    for (i = 0; i < size_info.AceCount; ++i) {
        if (!GetAce(new_dacl, i, &ace)) {
            printf ("GetAce Error: %u\n", GetLastError());
            ret = -1;
            goto cleanup;
        }

        if (ace->AceType == ACCESS_DENIED_ACE_TYPE) {
            deny_ace = (ACCESS_DENIED_ACE *)ace;
            if (deny_ace->Mask == WIN32_WRITE_ACCESS_MASK) {
                DeleteAce(new_dacl, i);
                break;
            }
        }
    }

    // Update path's ACL

    res = SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, new_dacl, NULL);
    if (ERROR_SUCCESS != res)  {
        printf( "SetNamedSecurityInfo Error %u\n", res );
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

    if (argc != 2 & argc != 3) {
        printf ("usage: set-ro [-u] path\n");
        exit(1);
    }

    if (argc == 2) {
        return set_path_read_only (argv[1]);
    } else {
        if (strcmp(argv[1], "-u") != 0) {
            printf ("usage: set-ro [-u] path\n");
            exit(1);
        }
        return unset_path_read_only (argv[2]);
    }

    return 0;
}
