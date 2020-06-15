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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <iomanip>
#include <string>

#include <oriutil/debug.h>
#include <oriutil/oriutil.h>
#include <oriutil/oricrypt.h>
#include <oriutil/key.h>
#include <oriutil/stream.h>
#include <ori/commit.h>

/********************************************************************
 *
 *
 * Commit
 *
 *
 ********************************************************************/

Commit::Commit()
    : version(0), flags(0), message(), treeObjId(), user(),
      snapshotName(), date(0), signature(""), graftRepo(),
      graftPath(), graftCommitId()
{
    version = COMMIT_VERSION;
    parents.first.clear();
    parents.second.clear();
}

Commit::~Commit()
{
}

void
Commit::setParents(ObjectHash p1, ObjectHash p2)
{
    parents.first = p1;
    parents.second = p2;
}

std::pair<ObjectHash, ObjectHash>
Commit::getParents() const
{
    return parents;
}

void
Commit::setMessage(const std::string &msg)
{
    message = msg;
}

std::string
Commit::getMessage() const
{
    return message;
}

void
Commit::setTree(const ObjectHash &tree)
{
    treeObjId = tree;
}

ObjectHash
Commit::getTree() const
{
    return treeObjId;
}

void
Commit::setUser(const std::string &user)
{
    this->user = user;
}

std::string
Commit::getUser() const
{
    return user;
}

void
Commit::setSnapshot(const std::string &snapshot)
{
    snapshotName = snapshot;
}

std::string
Commit::getSnapshot() const
{
    return snapshotName;
}

void
Commit::setTime(time_t t)
{
    date = t;
}

time_t
Commit::getTime() const
{
    return date;
}

void
Commit::sign(const PrivateKey &key)
{
    std::string blob = getBlob(/* withSignature */false);

    flags |= COMMIT_FLAG_HAS_SIGNATURE;
    signature = key.sign(blob);
}

bool
Commit::verify(const PublicKey &key)
{
    const std::string blob = getBlob(/* withSignature */false);

    if (~flags & COMMIT_FLAG_HAS_SIGNATURE)
        return false;

    return key.verify(blob, signature);
}

bool
Commit::hasSignature()
{
    return flags & COMMIT_FLAG_HAS_SIGNATURE;
}

void
Commit::setGraft(const std::string &repo,
                 const std::string &path,
                 const ObjectHash &commitId)
{
    flags |= COMMIT_FLAG_IS_GRAFT;
    graftRepo = repo;
    graftPath = path;
    graftCommitId = commitId;
}

std::pair<std::string, std::string>
Commit::getGraftRepo() const
{
    return std::make_pair(graftRepo, graftPath);
}

ObjectHash
Commit::getGraftCommit() const
{
    return graftCommitId;
}

std::string
Commit::getBlob(bool withSignature) const
{
    strwstream ss;

    ss.enableTypes();

    ss.writeUInt32(version);
    if (withSignature) {
        ss.writeUInt32(flags);
    } else {
        ss.writeUInt32(flags & ~COMMIT_FLAG_HAS_SIGNATURE);
    }

    ss.writeHash(treeObjId);
    if (!parents.second.isEmpty()) {
        ss.writeUInt8(2);
        ss.writeHash(parents.first);
        ss.writeHash(parents.second);
    } else if (!parents.first.isEmpty()) {
        ss.writeUInt8(1);
        ss.writeHash(parents.first);
    } else {
        ss.writeUInt8(0);
    }

    ss.writePStr(user);
    ss.writeUInt64(date);
    ss.writePStr(snapshotName);

    if (flags & COMMIT_FLAG_IS_GRAFT) {
        assert(graftPath != "");
        assert(!graftCommitId.isEmpty());

        ss.writePStr(graftRepo);
        ss.writePStr(graftPath);
        ss.writeHash(graftCommitId);
    }

    if (withSignature) {
        if (flags & COMMIT_FLAG_HAS_SIGNATURE) {
            // XXX: Write key fingerprint
            ss.writeLPStr(signature);
        }
    }

    ss.writePStr(message);

    return ss.str();
}

void
Commit::fromBlob(const std::string &blob)
{
    strstream ss(blob);

    ss.enableTypes();

    version = ss.readUInt32();
    flags = ss.readUInt32();

    if (version > COMMIT_VERSION) {
        std::cout << "Unsupported Commit object version: " << std::hex << std::setw(8)
             << std::setfill('0') << version << std::endl;
        NOT_IMPLEMENTED(false);
    }

    ss.readHash(treeObjId);
    const uint8_t numParents = ss.readUInt8();
    if (numParents == 2) {
        ss.readHash(parents.first);
        ss.readHash(parents.second);
    } else if (numParents == 1) {
        ss.readHash(parents.first);
    }

    ss.readPStr(user);
    date = ss.readUInt64();
    ss.readPStr(snapshotName);

    if (flags & COMMIT_FLAG_IS_GRAFT) {
        ss.readPStr(graftRepo);
        ss.readPStr(graftPath);
        ss.readHash(graftCommitId);

        assert(graftPath != "");
        assert(!graftCommitId.isEmpty());
    }

    if (flags & COMMIT_FLAG_HAS_SIGNATURE) {
        ss.readLPStr(signature);
    }

    ss.readPStr(message);
}

ObjectHash
Commit::hash() const
{
    const std::string &blob = getBlob();
    const ObjectHash h = OriCrypt_HashString(blob);
    /*fprintf(stderr, "Commit blob len %lu, hash %s\n", blob.size(),
            h.hex().c_str());
    OriDebug_PrintHex(blob);*/
    return h;
}

void
Commit::print() const
{
    time_t timeVal = date;
    char timeStr[26];

    ctime_r(&timeVal, timeStr);

    std::cout << "Version: 0x" << std::hex << std::setw(8) << std::setfill('0') << version << std::endl;
    std::cout << "Flags: 0x" << std::hex << std::setw(8) << std::setfill('0') << flags << std::endl;
    std::cout << "Parents: "
         << (parents.first.isEmpty() ? "" : parents.first.hex())
         << " "
         << (parents.second.isEmpty() ? "" : parents.second.hex()) << std::endl;
    std::cout << "Tree:    " << treeObjId.hex() << std::endl;
    std::cout << "Author:  " << user << std::endl;
    std::cout << "Date:    " << timeStr;
    if (flags & COMMIT_FLAG_HAS_SIGNATURE) {
        std::cout << "Signature: ";
        OriDebug_PrintHex(signature.data(), 0, signature.length());
        std::cout << std::endl;
    }
    if (!graftCommitId.isEmpty()) {
        std::cout << "Graft Repo: " << graftRepo << std::endl;
        std::cout << "Graft Path: " << graftPath << std::endl;
        std::cout << "Graft Commit: " << graftCommitId.hex() << std::endl;
    }
    std::cout << "----- BEGIN MESSAGE -----" << std::endl;
    std::cout << message << std::endl;
    std::cout << "----- END MESSAGE -----" << std::endl;
}

