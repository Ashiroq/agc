#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define CHUNK 16384

// TODO: Trees

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
int inf(FILE *source, FILE *dest)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            return Z_ERRNO;
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return ret;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

int def_with_header(FILE* source, FILE* dest, int level, const char* header, int hsize)
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

    /* deflating header */
    char* hcopy = malloc(hsize * sizeof(hcopy[0]));
    strcpy(hcopy, header);
    stream.next_in = hcopy;
    stream.avail_in = hsize;
    do {
        stream.avail_out = CHUNK;
        stream.next_out = out;
        ret = deflate(&stream, flush);
        assert(ret != Z_STREAM_ERROR);
        amount = CHUNK - stream.avail_out;
        if(fwrite(out, 1, amount, dest) != amount || ferror(dest)) {
            deflateEnd(&stream);
            return Z_ERRNO;
        }
    } while(stream.avail_out == 0);
    assert(stream.avail_in == 0);
    free(hcopy);

    /* deflating data until eof */
    do {
        stream.avail_in = fread(in, 1, CHUNK, source);
        if(ferror(source)) {
            deflateEnd(&stream);
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
                deflateEnd(&stream);
                return Z_ERRNO;
            }
        } while(stream.avail_out == 0);
        assert(stream.avail_in == 0);
    } while(flush != Z_FINISH);
    assert(ret == Z_STREAM_END);

    deflateEnd(&stream);
    return Z_OK;
}

int addFile(const char* name)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char buffer[CHUNK];
    SHA_CTX ctx;
    int amount;

    FILE* src = fopen(name, "rb");
    if(src == NULL)
        return 19;
    SHA1_Init(&ctx);
    struct stat st = {0};
    assert(stat(name, &st) == 0);

    /* calculating hash with added header */
    char header[100];
    int hsize = sprintf(header, "blob %d", st.st_size);
    SHA1_Update(&ctx, header, hsize + 1);               /* +1 because \0 is needed */
    while((amount = fread(buffer, 1, CHUNK, src)) != 0)
        SHA1_Update(&ctx, buffer, amount);
    SHA1_Final(hash, &ctx);

    char* hexhash = malloc((2 * SHA_DIGEST_LENGTH + 1) * sizeof(hexhash[0]));
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(hexhash + 2*i, "%02x", hash[i]);

    /* building hash-based path for file */
    char path[13 + 42] = ".agc/objects/";
    memcpy(path+13, hexhash, 2);            /* append directory name */
    path[15] = '/';
    struct stat st2 = {0};
    if(stat(path, &st2) == -1)
        mkdir(path, 0700);
    memcpy(path+16, hexhash+2, 38);         /* append file name */
    path[54] = '\0';

    printf("%s\n", hexhash);
    free(hexhash);

    FILE* dest = fopen(path, "wb");
    /* go back to beginning of file after hashing */
    rewind(src);
    /* file compression with header  */
    int ret = def_with_header(src, dest, Z_DEFAULT_COMPRESSION, header, hsize + 1);

    fclose(src);
    fclose(dest);
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
        return err;
    }
    else if(strcmp(argv[1], "cat") == 0) {
        FILE* src = fopen(argv[2], "rb");
        FILE* dest = fopen("testdest", "wb");
        int ret = inf(src, dest);
        return ret;
    }
    else {
        printf("Invalid command");
    }
    return 0;
}
