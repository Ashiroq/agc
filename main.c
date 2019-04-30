#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <assert.h>
#include <string.h>

#define CHUNK 16384

int compressFile(FILE* source, FILE* dest, int level)
{
    int ret, flush;
    unsigned int amount;
    z_stream stream;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    ret = deflateInit(&stream, level);
    if(ret != Z_OK)
        return ret;

    do {
        stream.avail_in = fread(in, 1, CHUNK, source);
        if(ferror(source)) {
            (void)deflateEnd(&stream);
            return Z_ERRNO;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        stream.next_in = in;
        do {
            stream.avail_out = CHUNK;
            stream.next_out = out;
            ret = deflate(&stream, flush);
            assert(ret != Z_STREAM_ERROR);
            amount = CHUNK - stream.avail_out;
            if(fwrite(out, 1, amount, dest) != amount || ferror(dest)) {
                (void)deflateEnd(&stream);
                return Z_ERRNO;
            }
        } while(stream.avail_out == 0);
        assert(stream.avail_in == 0);
    } while(flush != Z_FINISH);
    assert(ret == Z_STREAM_END);

    (void)deflateEnd(&stream);
    return Z_OK;
}

int addFile(const char* name)
{
    unsigned char hash[40];
    SHA1(name, strlen(name), hash);

    char tmp = hash[3];
    hash[3] = '\0';
    struct stat st = {0};
    if(stat(hash, &st) == -1) {
        mkdir(hash, 0700);
    }
    hash[3] = tmp;
    FILE* obj = fopen(hash+2, "w");
    FILE* src = fopen(name, "r");
    int ret = compressFile(src, obj, 6);
    return ret;
}

int main(int argc, char** argv)
{
    if(argc < 2) {
        fputs("Usage: agc init/add filename", stderr);
        return 1;
    }

    if(strcmp(argv[1], "init") == 0) {
        struct stat st = {0};
        if(stat(".agc/", &st) == -1) {
            mkdir(".agc/", 0700);
            mkdir(".agc/objects", 0700);
            mkdir(".agc/refs", 0700);
            mkdir(".agc/refs/heads", 0700);
        }
    }
    else if(strcmp(argv[1], "add") == 0) {
        struct stat st = {0};
        if(stat(argv[2], &st) == -1) {
            fputs("fatal: cannot find file", stderr);
            return 2;
        }
        if(argc < 3) {
            fputs("Usage: agc init/add filename", stderr);
            return 1;
        }
        int err = addFile(argv[2]);
        if(err != 0) {
            printf("error %d: cannot add file", err);
            return err;
        }
    }
    else {
        printf("Invalid command");
    }
    return 0;
}
