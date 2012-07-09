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

#include <string>
#include <set>
#include <queue>
#include <iostream>

#include "debug.h"
#include "util.h"
#include "object.h"
#include "largeblob.h"

#include "repo.h"
#include "localrepo.h"
#include "sshrepo.h"

using namespace std;


/*
 * Repo
 */

Repo::Repo() {
}

Repo::~Repo() {
}



/*
 * High-level operations
 */

int Repo::addObject(const ObjectInfo &info, const string &payload)
{
    assert(info.hash != ""); // hash must be included
    assert(info.type != Object::Null);

    if (info.getCompressed()) {
        bytestream *ss = new strstream(payload);
        lzmastream bs(ss, true);
        return addObjectRaw(info, &bs);
    }
    else {
        strstream ss(payload);
        return addObjectRaw(info, &ss);
    }
}

void
Repo::copyFrom(Object *other)
{
    bytestream::ap bs(other->getStoredPayloadStream());
    addObjectRaw(other->getInfo(), bs.get());
}

/*
 * Add a blob to the repository. This is a low-level interface.
 */
string
Repo::addBlob(Object::Type type, const string &blob)
{
    string hash = Util_HashString(blob);
    ObjectInfo info(hash.c_str());
    info.type = type;
    //info.flags = ...;
    addObject(info, blob);
    return hash;
}

/*
 * Get an object length.
 */
size_t
Repo::getObjectLength(const string &objId)
{
    Object::ap o(getObject(objId));
    // XXX: Add better error handling
    if (!o.get())
        return 0;
    return o->getInfo().payload_size;
}

/*
 * Get the object type.
 */
Object::Type
Repo::getObjectType(const string &objId)
{
    Object::ap o(this->getObject(objId));
    if (!o.get()) {
        printf("Couldn't get object %s\n", objId.c_str());
        return Object::Null;
    }
    return o->getInfo().type;
}

Tree
Repo::getTree(const std::string &treeId)
{
    Object::ap o(getObject(treeId));
    string blob = o->getPayload();

    assert(o->getInfo().type == Object::Tree);

    Tree t;
    t.fromBlob(blob);

    return t;
}

