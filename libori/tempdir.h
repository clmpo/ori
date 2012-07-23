#ifndef __TEMPDIR_H__
#define __TEMPDIR_H__

#include <set>
#include <vector>
#include <string>
#include <tr1/memory>
#include <tr1/unordered_map>

#include "repo.h"
#include "commit.h"
#include "debug.h"
#include "index.h"

/** Class for managing a temporary directory of objects.
  * Uses an append-only log for keeping track of objects.
  */
class TempDir : public Repo
{
public:
    TempDir(const std::string &dirpath);
    ~TempDir();

    typedef std::tr1::shared_ptr<TempDir> sp;

    std::string pathTo(const std::string &file);
    /// Temp files are deleted along with the directory
    std::string newTempFile();
    
    // Repo implementation
    std::string getHead() { NOT_IMPLEMENTED(false); }
    Object::sp getObject(const std::string &objId);
    bool hasObject(const std::string &objId);
    std::set<ObjectInfo> listObjects();
    std::vector<Commit> listCommits() { NOT_IMPLEMENTED(false); }
    int addObjectRaw(const ObjectInfo &info, bytestream *bs);
    void addBackref(const std::string &referer, const std::string &refers_to)
    { return; } // TODO

    std::string dirpath;

private:
    Index index;
    int objects_fd;
    std::tr1::unordered_map<std::string, off_t> offsets;
};

class TempObject : public Object
{
public:
    TempObject(int fd, off_t off, size_t len, const ObjectInfo &info);

    bytestream::ap getPayloadStream();
    bytestream::ap getStoredPayloadStream();
    size_t getStoredPayloadSize();

private:
    int fd;
    off_t off;
    size_t len;
};

#endif
