#ifndef SEAFILE_SESSION_H
#define SEAFILE_SESSION_H

#include <stdint.h>
#include <glib.h>

#include <seaf-db.h>

#include "block-mgr.h"
#include "fs-mgr.h"
#include "branch-mgr.h"
#include "commit-mgr.h"
#include "repo-mgr.h"
#include "user-mgr.h"


typedef struct _SeafileSession SeafileSession;

struct _SeafileSession {
    char                *seaf_dir;
    char                *tmp_file_dir;
    /* Config that's only loaded on start */
    GKeyFile            *config;
    SeafDB              *db;

    SeafBlockManager    *block_mgr;
    SeafFSManager       *fs_mgr;
    SeafBranchManager   *branch_mgr;
    SeafCommitManager   *commit_mgr;
    SeafRepoManager     *repo_mgr;
    FuseUserManager     *user_mgr;
};

extern SeafileSession *seaf;

SeafileSession *
seafile_session_new (const char *seafile_dir,
                     char *ccnet_dir);

int
seafile_session_init (SeafileSession *session);

int
seafile_session_start (SeafileSession *session);

#endif
