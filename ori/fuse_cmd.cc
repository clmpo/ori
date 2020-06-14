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
#include <string.h>

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string>

#include <oriutil/orifile.h>

#include "fuse_cmd.h"

using namespace std;

bool OF_HasFuse()
{
    return OF_ControlPath() != "";
}

std::string OF_RootPath()
{
    char *cwdbuf = getcwd(NULL, 0);
    std::string path = cwdbuf;
    free(cwdbuf);

    while (path.size() > 0) {
        std::string control_path = path + "/" + ORI_CONTROL_FILENAME;
        if (OriFile_Exists(control_path)) {
            return path;
        }
        path = OriFile_Dirname(path);
    }

    return "";
}

std::string OF_ControlPath()
{
    char *cwdbuf = getcwd(NULL, 0);
    std::string path = cwdbuf;
    free(cwdbuf);

    while (path.size() > 0) {
        const std::string control_path = path + "/" + ORI_CONTROL_FILENAME;
        if (OriFile_Exists(control_path)) {
            return control_path;
        }
        path = OriFile_Dirname(path);
    }

    return "";
}

std::string OF_RepoPath()
{
    const std::string controlPath = OF_ControlPath();
    if (controlPath.empty())
        return "";

    const int fd = open(controlPath.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("OF_RepoPath: open");
        return "";
    }

    struct stat sb;
    int status = fstat(fd, &sb);
    if (status < 0) {
        perror("OF_RepoPath: fstat");
        return "";
    }

    char buf[1024];
    status = read(fd, buf, sb.st_size);
    if (status < 0) {
        perror("OF_RepoPath: read");
        return "";
    }

    buf[status] = '\0';

    return std::string(buf);
}

