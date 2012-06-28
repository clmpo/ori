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
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

#include <openssl/sha.h>

#ifdef OPENSSL_NO_SHA256
#error "SHA256 not supported!"
#endif

#include "debug.h"
#include "object.h"

using namespace std;

/*
 * ObjectInfo
 */
Object::ObjectInfo::ObjectInfo()
    : type(Object::Null), flags(0), payload_size(0)
{
    memset(hash, 0, 2*SHA256_DIGEST_LENGTH); // TODO
}

ssize_t Object::ObjectInfo::writeTo(int fd, bool seekable) {
    const char *type_str = NULL;
    switch (type) {
        case Commit:    type_str = "CMMT"; break;
        case Tree:      type_str = "TREE"; break;
        case Blob:      type_str = "BLOB"; break;
        case LargeBlob: type_str = "LGBL"; break;
        case Purged:    type_str = "PURG"; break;
        default:
            printf("Unknown object type!\n");
            assert(false);
            return -1;
    }

    ssize_t status;
    if (seekable) {
        status = pwrite(fd, type_str, ORI_OBJECT_TYPESIZE, 0);
        if (status < 0) return status;
        assert(status == ORI_OBJECT_TYPESIZE);

        status = pwrite(fd, &flags, ORI_OBJECT_FLAGSSIZE, 4);
        if (status < 0) return status;
        assert(status == ORI_OBJECT_FLAGSSIZE);

        status = pwrite(fd, &payload_size, ORI_OBJECT_SIZE, 8);
        if (status < 0) return status;
        assert(status == ORI_OBJECT_SIZE);

        return 0;
    }
    else {
        // TODO!!! use write() instead
        assert(false);
    }
}



/*
 * Object
 */
Object::Object()
{
    fd = -1;
}

Object::~Object()
{
    close();
}

/*
 * Create a new object.
 */
int
Object::create(const string &path, Type type, uint32_t flags)
{
    int status;

    objPath = path;

    fd = ::open(path.c_str(), O_CREAT | O_RDWR,
	        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
	return -errno;

    info.type = type;
    info.flags = flags;
    status = info.writeTo(fd);
    if (status < 0)
        return -errno;

    // Stored length
    status = pwrite(fd, "\0\0\0\0\0\0\0\0",
            ORI_OBJECT_SIZE, 16);
    if (status < 0)
        return -errno;
    assert(status == ORI_OBJECT_SIZE);

    return 0;
}

/*
 * Open an existing object read-only.
 */
int
Object::open(const string &path)
{
    int status;
    char buf[5];

    objPath = path;

    fd = ::open(path.c_str(), O_RDWR);
    if (fd < 0)
	return -errno;

    buf[4] = '\0';
    status = pread(fd, buf, ORI_OBJECT_TYPESIZE, 0);
    if (status < 0) {
	::close(fd);
	fd = -1;
	return -errno;
    }

    assert(status == ORI_OBJECT_TYPESIZE);

    Type t;
    if (strcmp(buf, "CMMT") == 0) {
        t = Commit;
    } else if (strcmp(buf, "TREE") == 0) {
        t = Tree;
    } else if (strcmp(buf, "BLOB") == 0) {
        t = Blob;
    } else if (strcmp(buf, "LGBL") == 0) {
        t = LargeBlob;
    } else if (strcmp(buf, "PURG") == 0) {
        t = Purged;
    } else {
        printf("Unknown object type!\n");
        assert(false);
    }

    info.type = t;

    status = pread(fd, (void *)&info.flags, ORI_OBJECT_FLAGSSIZE, 4);
    if (status < 0) {
        close();
        return -errno;
    }

    status = pread(fd, (void *)&info.payload_size, ORI_OBJECT_SIZE, 8);
    if (status < 0) {
	::close(fd);
	fd = -1;
	t = Null;
	return -errno;
    }

    status = pread(fd, (void *)&storedLen, ORI_OBJECT_SIZE, 16);
    if (status < 0) {
        close();
        return -errno;
    }

    return 0;
}

/*
 * Close the object file.
 */
void
Object::close()
{
    if (fd != -1)
        ::close(fd);

    fd = -1;
    storedLen = 0;
    objPath = "";
    info = ObjectInfo();
}

/*
 * Get the header info.
 */
Object::ObjectInfo &
Object::getInfo() {
    return info;
}

/*
 * Read the object type.
 */
Object::Type
Object::getType()
{
    return info.type;
}

/*
 * Get the on-disk file size including the object header.
 */
size_t
Object::getDiskSize()
{
    struct stat sb;

    if (fstat(fd, &sb) < 0) {
	return -errno;
    }

    return sb.st_size;
}

/*
 * Get the size of the payload when stored on disk (e.g. after compression)
 */
size_t
Object::getStoredPayloadSize() {
    return storedLen;
}

/* Flags */

bool Object::getCompressed() {
    return info.flags & ORI_FLAG_COMPRESSED;
}

#define COPYFILE_BUFSZ	4096

/*
 * Purge object.
 */
int
Object::purge()
{
    int status;

    // XXX: Support for backrefs and large blobs
    NOT_IMPLEMENTED(ORI_OBJECT_HDRSIZE + storedLen == getDiskSize());
    NOT_IMPLEMENTED(info.type == Blob);

    status = pwrite(fd, "PURG", ORI_OBJECT_TYPESIZE, 0);
    info.type = Purged;
    if (status < 0)
	return -errno;

    status = ftruncate(fd, ORI_OBJECT_HDRSIZE);
    if (status < 0)
	return -errno;

    return 0;
}

/*
 * Append the specified file into the object.
 */
int
Object::appendFile(const string &path)
{
    int srcFd;
    char buf[COPYFILE_BUFSZ];
    struct stat sb;
    int64_t bytesLeft;
    int64_t bytesRead, bytesWritten;

    lzma_stream strm = LZMA_STREAM_INIT;
    if (getCompressed()) setupLzma(&strm, true);

    if (lseek(fd, ORI_OBJECT_HDRSIZE, SEEK_SET) != ORI_OBJECT_HDRSIZE) {
        return -errno;
    }

    srcFd = ::open(path.c_str(), O_RDONLY);
    if (srcFd < 0)
        return -errno;

    if (fstat(srcFd, &sb) < 0) {
	::close(srcFd);
	return -errno;
    }

    info.payload_size = sb.st_size;
    if (info.writeTo(fd) < 0) {
        ::close(srcFd);
        return -errno;
    }

    bytesLeft = sb.st_size;
    while(bytesLeft > 0) {
        bytesRead = read(srcFd, buf, MIN(bytesLeft, COPYFILE_BUFSZ));
        if (bytesRead < 0) {
            if (errno == EINTR)
            continue;
            goto error;
        }

        if (getCompressed()) {
            strm.next_in = (uint8_t*)buf;
            strm.avail_in = bytesRead;
            appendLzma(fd, &strm, LZMA_RUN);
        }
        else {
retryWrite:
            bytesWritten = write(fd, buf, bytesRead);
            if (bytesWritten < 0) {
                if (errno == EINTR)
                    goto retryWrite;
                goto error;
            }

            // XXX: Need to handle this case!
            assert(bytesRead == bytesWritten);
        }

        bytesLeft -= bytesRead;
    }

    // Write final (post-compression) size
    if (getCompressed()) {
        appendLzma(fd, &strm, LZMA_FINISH);
        storedLen = strm.total_out;
    }
    else {
        storedLen = info.payload_size;
    }

    if (pwrite(fd, (void *)&storedLen, ORI_OBJECT_SIZE, 16) != ORI_OBJECT_SIZE)
        return -errno;

    ::close(srcFd);
    return sb.st_size;

error:
    ::close(srcFd);
    return -errno;
}

/*
 * Extract the contents of the object file into the specified path.
 */
int
Object::extractFile(const string &path)
{
    std::auto_ptr<bytestream> bs(getPayloadStream());
    if (bs->error()) return -bs->errnum();

    int dstFd = ::open(path.c_str(), O_WRONLY | O_CREAT,
		   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (dstFd < 0)
        return -errno;

    uint8_t buf[COPYFILE_BUFSZ];
    while (!bs->ended()) {
        size_t bytesRead = bs->read(buf, COPYFILE_BUFSZ);
        if (bs->error()) goto bs_error;
retryWrite:
        ssize_t bytesWritten = write(dstFd, buf, bytesRead);
        if (bytesWritten < 0) {
            if (errno == EINTR)
                goto retryWrite;
            goto error;
        }
    }

    ::close(dstFd);
    return info.payload_size;

bs_error:
    unlink(path.c_str());
    ::close(dstFd);
    return -bs->errnum();
error:
    unlink(path.c_str());
    ::close(dstFd);
    return -errno;
}

/*
 * Append a blob to the object file.
 */
int
Object::appendBlob(const string &blob)
{
    int status;

    info.payload_size = blob.length();
    if (info.writeTo(fd) < 0) {
        return -errno;
    }

    if (getCompressed()) {
        if (lseek(fd, ORI_OBJECT_HDRSIZE, SEEK_SET) != ORI_OBJECT_HDRSIZE)
            return -errno;

        lzma_stream strm = LZMA_STREAM_INIT;
        setupLzma(&strm, true);

        strm.next_in = (const uint8_t *)blob.data();
        strm.avail_in = blob.length();
        appendLzma(fd, &strm, LZMA_RUN);
        appendLzma(fd, &strm, LZMA_FINISH);

        storedLen = strm.total_out;
    }
    else {
        status = pwrite(fd, blob.data(), blob.length(), ORI_OBJECT_HDRSIZE);
        if (status < 0)
            return -errno;

        assert(status == blob.length());

        storedLen = blob.length();
    }

    status = pwrite(fd, (void *)&storedLen, ORI_OBJECT_SIZE, 16);
    if (status < 0)
        return -errno;

    return 0;
}

/*
 * Extract the blob from the object file.
 */
string
Object::extractBlob()
{
    std::auto_ptr<bytestream> bs(getPayloadStream());
    if (bs->error()) return "";

    std::string rval;
    rval.resize(info.payload_size);
    bs->read((uint8_t*)rval.data(), info.payload_size);
    if (bs->error()) return "";

    return rval;
}

/*
 * Recompute the SHA-256 hash to verify the file.
 */
string
Object::computeHash()
{
    std::auto_ptr<bytestream> bs(getPayloadStream());
    if (bs->error()) return "";

    uint8_t buf[COPYFILE_BUFSZ];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    stringstream rval;

    SHA256_CTX state;
    SHA256_Init(&state);

    while(!bs->ended()) {
        size_t bytesRead = bs->read(buf, COPYFILE_BUFSZ);
        if (bs->error()) {
            return "";
        }

        SHA256_Update(&state, buf, bytesRead);
    }

    SHA256_Final(hash, &state);

    // Convert into string.
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
	rval << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return rval.str();
}

bytestream *Object::getPayloadStream() {
    if (getCompressed()) {
        return new lzmastream(new diskstream(fd, ORI_OBJECT_HDRSIZE, storedLen));
    }
    else {
        return new diskstream(fd, ORI_OBJECT_HDRSIZE, storedLen);
    }
}


/*
 * Metadata operations
 */

#define OFF_MD_HASH (ORI_OBJECT_HDRSIZE + getStoredPayloadSize())

/* Organization of metadata on disk: immediately following the stored data, the
 * SHA256 checksum of all the metadata (size ORI_MD_HASHSIZE); following that, a
 * plain unpadded array of metadata entries. Each entry begins with a 2-byte
 * identifier followed by 2 bytes denoting the length in bytes of the entry
 * followed by the entry itself.
 */
void Object::addMetadataEntry(MdType type, const std::string &data) {
    assert(checkMetadata());

    off_t offset = getDiskSize();
    if (offset == OFF_MD_HASH) {
        offset += ORI_MD_HASHSIZE;
    }

    int err = pwrite(fd, _getIdForMdType(type), 2, offset);
    assert(err == 2);
    uint16_t len = data.length();
    err = pwrite(fd, &len, 2, offset + 2);
    assert(err == 2);

    err = pwrite(fd, data.data(), data.length(), offset + 4);
    assert((size_t)err == data.length());
    fsync(fd);

    std::string hash = computeMetadataHash();
    assert(hash != "");
    err = pwrite(fd, hash.data(), ORI_MD_HASHSIZE, OFF_MD_HASH);
    assert(err == ORI_MD_HASHSIZE);
}

std::string Object::computeMetadataHash() {
    off_t offset = OFF_MD_HASH + ORI_MD_HASHSIZE;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        return "";
    }

    SHA256_CTX state;
    SHA256_Init(&state);

    if ((off_t)getDiskSize() < offset)
        return "";

    size_t bytesLeft = getDiskSize() - offset;
    while(bytesLeft > 0) {
        uint8_t buf[COPYFILE_BUFSZ];
        int bytesRead = read(fd, buf, MIN(bytesLeft, COPYFILE_BUFSZ));
        if (bytesRead < 0) {
            if (errno == EINTR)
                continue;
            return "";
        }

        SHA256_Update(&state, buf, bytesRead);
        bytesLeft -= bytesRead;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &state);

    std::string rval;
    rval.assign((char *)hash, SHA256_DIGEST_LENGTH);
    return rval;
}

bool
Object::checkMetadata()
{
    if (getDiskSize() <= OFF_MD_HASH) {
        // No metadata to check
        return true;
    }

    char disk_hash[ORI_MD_HASHSIZE+1];
    int status = pread(fd, disk_hash, ORI_MD_HASHSIZE, OFF_MD_HASH);
    if (status < 0) {
        perror("pread");
        return false;
    }
    disk_hash[ORI_MD_HASHSIZE] = '\0';

    std::string computed_hash = computeMetadataHash();

    if (strcmp(computed_hash.c_str(), disk_hash) == 0)
        return true;
    return false;
}

void
Object::clearMetadata()
{
    int status;

    status = ftruncate(fd, OFF_MD_HASH);
    assert(status == 0);
}


void
Object::addBackref(const string &objId, Object::BRState state)
{
    string buf = objId;

    assert(objId.length() == 2 * SHA256_DIGEST_LENGTH);
    assert(state == BRRef || state == BRPurged);

    if (state == BRRef) {
        buf += "R";
    }
    if (state == BRPurged) {
        buf += "P";
    }

    addMetadataEntry(MdBackref, buf);
}

void
Object::updateBackref(const string &objId, Object::BRState state)
{
    map<string, BRState> backrefs;
    map<string, BRState>::iterator it;

    assert(objId.length() == SHA256_DIGEST_LENGTH);
    assert(state == BRRef || state == BRPurged);

    backrefs = getBackref();
    backrefs[objId] = state;

    /*
     * XXX: Crash Recovery
     *
     * Either we can log here to make crash recovery easier, otherwise
     * we should just write the single modified byte.  That should always
     * translate to a single sector write, which is atomic.
     */

    clearMetadata(); // was clearBackref

    for (it = backrefs.begin(); it != backrefs.end(); it++) {
	addBackref((*it).first, (*it).second);
    }
}

map<string, Object::BRState>
Object::getBackref()
{
    map<string, BRState> rval;

    off_t md_off = OFF_MD_HASH + ORI_MD_HASHSIZE;
    if ((off_t)getDiskSize() < md_off) {
        // No metadata
        return rval;
    }

    // Load all metadata into memory
    size_t backrefSize = getDiskSize() - md_off;

    std::vector<uint8_t> buf;
    buf.resize(backrefSize);
    int status = pread(fd, &buf[0], backrefSize, md_off);
    assert(status == backrefSize);

    // XXX: more generic way to iterate over metadata
    uint8_t *ptr = &buf[0];
    while ((ptr - &buf[0]) < backrefSize) {
        MdType md_type = _getMdTypeForStr((const char *)ptr);
        size_t md_len = *((uint16_t*)(ptr+2));

        ptr += 4;
        assert(ptr + md_len <= &buf[0] + backrefSize);

        if (md_type == MdBackref) {
            assert(md_len == 2*SHA256_DIGEST_LENGTH + 1);

            string objId;
            objId.assign((char *)ptr, 2*SHA256_DIGEST_LENGTH);

            char ref_type = *(ptr + 2*SHA256_DIGEST_LENGTH);
            if (ref_type == 'R') {
                rval[objId] = BRRef;
            } else if (ref_type == 'P') {
                rval[objId] = BRPurged;
            } else {
                assert(false);
            }
        }

        ptr += md_len;
    }

    return rval;
}



/*
 * Private methods
 */

// Code from xz_pipe_comp.c in xz examples

void Object::setupLzma(lzma_stream *strm, bool encode) {
    lzma_ret ret_xz;
    if (encode) {
        ret_xz = lzma_easy_encoder(strm, 0, LZMA_CHECK_NONE);
    }
    else {
        ret_xz = lzma_stream_decoder(strm, UINT64_MAX, 0);
    }
    assert(ret_xz == LZMA_OK);
}

bool Object::appendLzma(int dstFd, lzma_stream *strm, lzma_action action) {
    uint8_t outbuf[COPYFILE_BUFSZ];
    do {
        strm->next_out = outbuf;
        strm->avail_out = COPYFILE_BUFSZ;

        lzma_ret ret_xz = lzma_code(strm, action);
        if (ret_xz == LZMA_OK || ret_xz == LZMA_STREAM_END) {
            size_t bytes_to_write = COPYFILE_BUFSZ - strm->avail_out;
            int err = write(dstFd, outbuf, bytes_to_write);
            if (err < 0) {
                // TODO: retry write if interrupted?
                return false;
            }
        }
        else {
            ori_log("lzma_code error: %d\n", (int)ret_xz);
            return false;
        }
    } while (strm->avail_out == 0); // i.e. output isn't finished

    return true;
}

const char *Object::_getIdForMdType(MdType type) {
    switch (type) {
    case MdBackref:
        return "BR";
    default:
        return NULL;
    }
}

Object::MdType Object::_getMdTypeForStr(const char *str) {
    if (str[0] == 'B') {
        if (str[1] == 'R') {
            return MdBackref;
        }
    }
    return MdNull;
}
