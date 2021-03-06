/*
 * Copyright (c) 2012-2013 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>

#include <string>
#include <iostream>

using namespace std;

#include <ori/version.h>
#include <oriutil/debug.h>
#include <ori/repo.h>
#include <ori/localrepo.h>
#include <ori/server.h>

LocalRepo repository;

/********************************************************************
 *
 *
 * Command Infrastructure
 *
 *
 ********************************************************************/

#define CMD_NEED_REPO           1
#define CMD_DEBUG               8

typedef struct Cmd {
    const char *name;
    const char *desc;
    int (*cmd)(int argc, char * const argv[]);
    void (*usage)(void);
    int flags;
} Cmd;

// General Operations
int cmd_addkey(int argc, char * const argv[]);
int cmd_branches(int argc, char * const argv[]);
int cmd_branch(int argc, char * const argv[]);
int cmd_checkout(int argc, char * const argv[]);
void usage_commit(void);
int cmd_commit(int argc, char * const argv[]);
int cmd_diff(int argc, char * const argv[]);
int cmd_filelog(int argc, char * const argv[]);
int cmd_findheads(int argc, char * const argv[]);
int cmd_gc(int argc, char * const argv[]);
void usage_graft(void);
int cmd_graft(int argc, char * const argv[]);
void usage_init(void);
int cmd_init(int argc, char * const argv[]);
void usage_list();
int cmd_list(int argc, char * const argv[]);
int cmd_listkeys(int argc, char * const argv[]);
int cmd_log(int argc, char * const argv[]);
int cmd_merge(int argc, char * const argv[]);
void usage_newfs();
int cmd_newfs(int argc, char * const argv[]);
int cmd_pull(int argc, char * const argv[]);
int cmd_remote(int argc, char * const argv[]);
void usage_removefs();
int cmd_removefs(int argc, char * const argv[]);
int cmd_removekey(int argc, char * const argv[]);
void usage_replicate(void);
int cmd_replicate(int argc, char * const argv[]);
int cmd_setkey(int argc, char * const argv[]);
int cmd_show(int argc, char * const argv[]);
void usage_snapshot(void);
int cmd_snapshot(int argc, char * const argv[]);
int cmd_snapshots(int argc, char * const argv[]);
int cmd_status(int argc, char * const argv[]);
int cmd_tip(int argc, char * const argv[]);

// Debug Operations
int cmd_purgesnapshot(int argc, char * const argv[]);
int cmd_sshserver(int argc, char * const argv[]); // Internal
int cmd_treediff(int argc, char * const argv[]);
static int cmd_help(int argc, char * const argv[]);
static int cmd_version(int argc, char * const argv[]);

static Cmd commands[] = {
    {
        "addkey",
        "Add a trusted public key to the repository",
        cmd_addkey,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "branch",
        "Set or print current branch (EXPERIMENTAL)",
        cmd_branch,
        nullptr,
        CMD_NEED_REPO | CMD_DEBUG,
    },
    {
        "branches",
        "List all available branches (EXPERIMENTAL)",
        cmd_branches,
        nullptr,
        CMD_NEED_REPO | CMD_DEBUG,
    },
    {
        "checkout",
        "Checkout a revision of the repository (DEBUG)",
        cmd_checkout,
        nullptr,
        CMD_NEED_REPO | CMD_DEBUG,
    },
    { // Deprecated
        "commit",
        "Commit changes into the repository (DEPRECATED)",
        cmd_commit,
        usage_commit,
        CMD_NEED_REPO | CMD_DEBUG,
    },
    {
        "diff",
        "Display a diff of the pending changes",
        cmd_diff,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "filelog",
        "Display a log of change to the specified file",
        cmd_filelog,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "findheads",
        "Find lost heads",
        cmd_findheads,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "gc",
        "Reclaim unused space",
        cmd_gc,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "graft",
        "Graft a subtree from a repository into the local repository",
        cmd_graft,
        usage_graft,
        0, /* Avoid CMD_NEED_REPO to allow aliasing of 'cp' */
    },
    {
        "help",
        "Show help for a given topic",
        cmd_help,
        nullptr,
        0,
    },
    {
        "init",
        "Initialize the repository (EXPERIMENTAL)",
        cmd_init,
        usage_init,
        CMD_DEBUG,
    },
    {
        "list",
        "List local file systems",
        cmd_list,
        usage_list,
        0,
    },
    {
        "listkeys",
        "Display a list of trusted public keys",
        cmd_listkeys,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "log",
        "Display a log of commits to the repository",
        cmd_log,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "merge",
        "Merge two heads",
        cmd_merge,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "newfs",
        "Create a new file system",
        cmd_newfs,
        usage_newfs,
        0,
    },
    {
        "pull",
        "Pull changes from a repository",
        cmd_pull,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "purgesnapshot",
        "Purge snapshot",
        cmd_purgesnapshot,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "remote",
        "Remote connection management",
        cmd_remote,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "removefs",
        "Remove a local replica",
        cmd_removefs,
        usage_removefs,
        0,
    },
    {
        "removekey",
        "Remove a public key from the repository",
        cmd_removekey,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "replicate",
        "Create a local replica",
        cmd_replicate,
        usage_replicate,
        0,
    },
    {
        "setkey",
        "Set the repository private key for signing commits",
        cmd_setkey,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "show",
        "Show repository information",
        cmd_show,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "snapshot",
        "Create a repository snapshot",
        cmd_snapshot,
        usage_snapshot,
        CMD_NEED_REPO,
    },
    {
        "snapshots",
        "List all snapshots available in the repository",
        cmd_snapshots,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "status",
        "Scan for changes since last commit",
        cmd_status,
        nullptr,
        CMD_NEED_REPO,
    },
    {
        "tip",
        "Print the latest commit on this branch",
        cmd_tip,
        nullptr,
        CMD_NEED_REPO,
    },
    /* Internal (always hidden) */
    {
        "sshserver",
        nullptr, // "Run a simple stdin/out server, intended for SSH access",
        cmd_sshserver,
        nullptr,
        0,
    },
    /* Debugging */
    {
        "treediff",
        "Compare two commits (DEBUG)",
        cmd_treediff,
        nullptr,
        CMD_NEED_REPO | CMD_DEBUG,
    },
    {
        "version",
        "Show version information",
        cmd_version,
        nullptr,
        CMD_DEBUG,
    },
    { nullptr, nullptr, nullptr, nullptr }
};

static int
lookupcmd(const char *cmd)
{
    int i;

    for (i = 0; commands[i].name != nullptr; i++)
    {
        if (strcmp(commands[i].name, cmd) == 0)
            return i;
    }

    return -1;
}

static int
cmd_help(int argc, char * const argv[])
{
    int i = 0;

    if (argc >= 2) {
        i = lookupcmd(argv[1]);
        if (i != -1 && commands[i].usage != nullptr) {
            commands[i].usage();
            return 0;
        }
        if (i == -1) {
            printf("Unknown command '%s'\n", argv[1]);
        } else {
            printf("No help for command '%s'\n", argv[1]);
        }
        return 0;
    }

    printf("Ori Distributed Personal File System (%s) - Command Line Interface\n\n",
            ORI_VERSION_STR);
    printf("Available commands:\n");
    for (i = 0; commands[i].name != nullptr; i++)
    {
#ifndef DEBUG
        if (commands[i].flags & CMD_DEBUG)
            continue;
#endif /* DEBUG */
        if (commands[i].desc != nullptr)
            printf("%-15s %s\n", commands[i].name, commands[i].desc);
    }

    printf("\nPlease report bugs to orifs-devel@stanford.edu\n");
    printf("Website: http://ori.scs.stanford.edu/\n");

    return 0;
}

static int
cmd_version(int argc, char * const argv[])
{
    printf("Ori Distributed Personal File System (%s) - Command Line Interface\n",
            ORI_VERSION_STR);
#ifdef GIT_VERSION
    printf("Git Commit Id: " GIT_VERSION "\n");
#endif
#if defined(DEBUG) || defined(ORI_DEBUG)
    printf("Build: DEBUG\n");
#elif defined(ORI_PERF)
    printf("Build: PERF\n");
#else
    printf("Build: RELEASE\n");
#endif

    return 0;
}

int
main(int argc, char *argv[])
{
    bool has_repo = false;
    int idx;

    if (argc == 1) {
        return cmd_help(0, nullptr);
    }

    idx = lookupcmd(argv[1]);
    if (idx == -1) {
        printf("Unknown command '%s'\n", argv[1]);
        cmd_help(0, nullptr);
        return 1;
    }

    // Open the repository for all command except the following
    if (commands[idx].flags & CMD_NEED_REPO)
    {
        try {
            repository.open();
            if (ori_open_log(repository.getLogPath()) < 0) {
                printf("Couldn't open log!\n");
                exit(1);
            }
            has_repo = true;
        } catch (std::exception &e) {
            // Fall through
        }
    }

    if (commands[idx].flags & CMD_NEED_REPO)
    {
        if (!has_repo) {
            printf("No repository found!\n");
            exit(1);
        }
    }


    DLOG("Executing '%s'", argv[1]);
    return commands[idx].cmd(argc-1, (char * const*)argv+1);
}

