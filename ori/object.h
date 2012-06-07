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

#ifndef __OBJECT_H__
#define __OBJECT_H__

#include <stdint.h>

#include <utility>
#include <string>

#define ORI_OBJECT_HDRSIZE	4

class Object
{
public:
    enum Type { Null, Commit, Tree, Blob };
    Object();
    ~Object();
    int create(const std::string &path, Type type);
    int open(const std::string &path);
    void close();
    Type getType();
    size_t getDiskSize();
    size_t getObjectSize();
    int appendFile(const std::string &path);
    int extractFile(const std::string &path);
    int appendBlob(const std::string &blob);
    std::string extractBlob();
    std::string computeHash();
private:
    int fd;
    Type t;
};

#endif /* __OBJECT_H__ */
