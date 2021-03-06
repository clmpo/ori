/*
 * Copyright (c) 2012 Stanford University
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <fcntl.h>

#include "logging.h"

FILE *logfd = nullptr;

void
ori_fuse_log_enable()
{
    if (logfd == nullptr) {
        logfd = fopen("fuse.log", "wb+");
        if (logfd == nullptr) {
            perror("fopen");
            exit(1);
        } 
    }
}

void
ori_fuse_log(const char *what, ...)
{
    va_list vl;
    va_start(vl, what);

    if (logfd == nullptr) {
        return;
    }

    vfprintf(logfd, what, vl);

#ifdef DEBUG
    fflush(logfd);
#endif
}

