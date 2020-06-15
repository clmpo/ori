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

#include <string>
#include <iostream>

#include <oriutil/orifile.h>
#include <oriutil/key.h>
#include <ori/localrepo.h>

extern LocalRepo repository;

int
cmd_setkey(int argc, char * const argv[])
{
    int status;
    const std::string rootPath = LocalRepo::findRootPath();

    if (rootPath == "") {
        std::cout << "No repository found!" << std::endl;
        return 1;
    }

    if (argc != 2)
    {
        std::cout << "Specify the path to your private key." << std::endl;
        std::cout << "usage: ori setkey <private_key>" << std::endl;
    }

    switch (Key_GetType(argv[1]))
    {
	case KeyType::Invalid:
	    std::cout << "File not found or invalid key." << std::endl;
	    return 1;
	case KeyType::Public:
	    std::cout << "This appears to be a private key please specify a public key."
		 << std::endl;
	    return 1;
	case KeyType::Private:
	default:
	    break;
    }

    PrivateKey priv = PrivateKey();
    try {
        priv.open(argv[1]);
    } catch (const std::exception& e) 
    {
        std::cout << "It appears that the key is invalid." << std::endl;
        return 1;
    }

    const int status = OriFile_Copy(argv[1], rootPath + ORI_PATH_PRIVATEKEY);
    if (status < 0)
    {
        std::cout << "Failed to copy the private key into the repository." << std::endl;
    }

    return 0;
}

