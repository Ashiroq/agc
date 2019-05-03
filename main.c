#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>

/* used in zlib */
#define CHUNK 16384

#define INDEX_SIGNATURE "DIRC"
#define INDEX_VERSION 2
#define INDEX_LOCATION ".git/index" /* change to .agc when ready */
#define OBJ_STORE_LOCATION ".agc/objects/"

/* size constants for freading, change requires changes in code */
#define SIGNATURE_SIZE 4
#define VERSION_SIZE 4
#define ENTRY_NUM_SIZE 4
#define CTIME_SIZE 4
#define CTIME_NSEC_SIZE 4
#define MTIME_SIZE 4
#define MTIME_NSEC_SIZE 4
#define DEV_SIZE 4
#define INO_SIZE 4
#define MODE_SIZE 4
#define UID_SIZE 4
#define GID_SIZE 4
#define SIZE_SIZE 4
#define HASH_SIZE 20
#define FLAGS_SIZE 2

// TODO: Provide procedure to translate error codes to messages
enum agc_error {
    AGC_SUCCESS = 0,
    AGC_NOT_ENOUGH_ARGS = 100,
    AGC_FILE_NOT_FOUND = 101,
    AGC_IO_ERROR = 102,
    AGC_INVALID_INDEX = 103,
    AGC_STRUCT_ERROR = 104
};

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
    char* hcopy = malloc(hsize * sizeof *hcopy);
    strcpy(hcopy, header);
    stream.next_in = (unsigned char*)hcopy;
    stream.avail_in = hsize;
    flush = strlen(hcopy) == 0 ? Z_FINISH : Z_NO_FLUSH;
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

int getheader(const char *name, const char *type, char **header, size_t *hsize)
{
    if(*header == NULL) {
        *header = malloc(100 * sizeof **header);
    }
    struct stat st = {0};
    int ret = stat(name, &st);
    if(ret != 0)
        return ret;
    strcpy(*header, type);
    *hsize = strlen(type);
    /* +1 \0 is header delimiter */
    *hsize += sprintf(*header + *hsize, "%ld", st.st_size) + 1;
    return 0;
}

// TODO: Docs
enum agc_error hash_object(const char *name, const char *header, const size_t headsize, char **hash, size_t *hsize)
{
    if(*hash == NULL) {
        *hsize = SHA_DIGEST_LENGTH;
        *hash = malloc(*hsize * sizeof **hash);
    }
    unsigned char buffer[CHUNK];
    SHA_CTX ctx;
    int amount;
    FILE* src = fopen(name, "rb");

    if(src == NULL)
        return AGC_IO_ERROR;

    /* calculating hash with added header */
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, header, headsize);
    while((amount = fread(buffer, 1, CHUNK, src)) != 0)
        SHA1_Update(&ctx, buffer, amount);
    SHA1_Final(*hash, &ctx);
    return AGC_SUCCESS;
}

// TODO: Docs
enum agc_error storefile(const char *name, const char *header, const size_t headsize, char *hash)
{
    /* building hash-based path for file */
    const char *storepath = OBJ_STORE_LOCATION;
    const size_t splen = strlen(storepath);

    // TODO: Explain this size calculation
    size_t psize = splen + 2 * SHA_DIGEST_LENGTH + 2;
    char *path = malloc(psize * sizeof *path);
    memcpy(path + splen, hash, 2);            /* append directory name */
    path[15] = '/';
    struct stat st2 = {0};
    if(stat(path, &st2) == -1)
        mkdir(path, 0700);
    memcpy(path + splen + 3, hash + 2, 38);         /* append file name */
    path[psize - 1] = '\0';

    /* file compression with header  */
    FILE *src = fopen(name, "r+b");
    if(src == NULL)
        return AGC_IO_ERROR;
    FILE *dest = fopen(path, "wb");
    if(dest == NULL)
        return AGC_IO_ERROR;
    int ret = def_with_header(src, dest, Z_DEFAULT_COMPRESSION, header, headsize);
    fclose(src);
    fclose(dest);
    free(path);
    return ret;
}

struct index {
    char sig[5];
    uint32_t ver;
    uint32_t num;
    struct entry *first;
};

struct entry {
    struct stat st;
    uint32_t mode;
    unsigned char hash[21];
    uint16_t flags;
    char *pathname;
    unsigned int namelen;
    struct entry *next;
};

enum agc_error read_index(struct index *data)
{
    FILE* idxf = fopen(INDEX_LOCATION, "r+b");
    if(idxf == NULL) {
        return AGC_IO_ERROR;
    }
    fread(data->sig, 1, SIGNATURE_SIZE, idxf);
    data->sig[4] = '\0'; /* used for printing */
    if(feof(idxf)) {
        /* index is empty */
        sprintf(data->sig, INDEX_SIGNATURE);
        data->ver = INDEX_VERSION;
        data->num = 0;
        fprintf(stderr, "index empty\n");
    }
    else {
        fread(&data->ver, 1, 4, idxf);
        data->ver = be32toh(data->ver);
        if(feof(idxf)) {
            /* cannot read header, invalid format */
            return AGC_INVALID_INDEX;
        }

        /* have to translate endian here and everywhere else */
        /* in writing index file as well: htobe32 etc. */
        fread(&data->num, 4, 1, idxf);
        data->num = be32toh(data->num);
        if(feof(idxf)) {
            /* cannot read header, invalid format */
            return AGC_INVALID_INDEX;
        }
        /* reading all existing entries into linked list */
        struct entry* ptr = NULL;
        data->first = NULL;
        for(int i = 0; i < data->num; i++) {
            struct entry *en = malloc(sizeof en);
            en->next = NULL;

            /* reading fields in order with endian translation */
            fread(&en->st.st_ctime, 1, CTIME_SIZE, idxf);
            en->st.st_ctime = be32toh(en->st.st_ctime);

            /* what to do with all these constant integers? */
            fread(&en->st.st_ctim.tv_nsec, 1, CTIME_NSEC_SIZE, idxf);
            en->st.st_ctim.tv_nsec = be32toh(en->st.st_ctim.tv_nsec);

            fread(&en->st.st_mtime, 1, MTIME_SIZE, idxf);
            en->st.st_mtime = be32toh(en->st.st_mtime);

            fread(&en->st.st_mtim.tv_nsec, 1, MTIME_NSEC_SIZE, idxf);
            en->st.st_mtim.tv_nsec = be32toh(en->st.st_mtim.tv_nsec);

            fread(&en->st.st_dev, 1, DEV_SIZE, idxf);
            en->st.st_dev = be32toh(en->st.st_dev);

            fread(&en->st.st_ino, 1, INO_SIZE, idxf);
            en->st.st_ino = be32toh(en->st.st_ino);

            fread(&en->mode, 1, MODE_SIZE, idxf);
            en->mode = be32toh(en->mode);

            fread(&en->st.st_uid, 1, UID_SIZE, idxf);
            en->st.st_uid = be32toh(en->st.st_uid);

            fread(&en->st.st_gid, 1, GID_SIZE, idxf);
            en->st.st_gid = be32toh(en->st.st_gid);

            fread(&en->st.st_size, 1, SIZE_SIZE, idxf);
            en->st.st_size = be32toh(en->st.st_size);

            fread(en->hash, 1, HASH_SIZE, idxf);

            fread(&en->flags, 1, FLAGS_SIZE, idxf);
            en->flags = be16toh(en->flags);

            en->pathname = NULL;
            size_t psize = 0;
            en->namelen = getdelim(&en->pathname, &psize, '\0', idxf);

            /* skipping padding null bytes */
            unsigned char skipped_byte;
            do {
                fread(&skipped_byte, 1, 1, idxf);
                /* skips one additional byte from next entry */
            } while(!feof(idxf) && skipped_byte == 0);
            fseek(idxf, -1L, SEEK_CUR);

            if(data->first == NULL)
                data->first = en;
            else
                ptr->next = en;
            ptr = en;

            /* just for debugging */
            fprintf(stderr, "%o\n", ptr->mode);
            fprintf(stderr, "flags: %x\n", ptr->flags);
            fprintf(stderr, "pathname: %s\n", ptr->pathname);
            fprintf(stderr, "hash: ");
            for(int j = 0; j < 21; j++)
                fprintf(stderr, "%x", ptr->hash[j]);
            fprintf(stderr, "\n");

            if(feof(idxf) && i + 1 < data->num) {
                /* not enough entries */
                return AGC_INVALID_INDEX;
            }
        }
        fprintf(stderr, "version: %d\n", data->ver);
    }
    return AGC_SUCCESS;
}

/* Write index structure to file at INDEX_LOCATION according to git
   index file format. */
enum agc_error write_index(struct index *data)
{
    // TODO: This

    return AGC_SUCCESS;
}

enum agc_error add_to_index(struct index *data, struct entry *node)
{
    if(data == NULL) {
        return AGC_STRUCT_ERROR;
    }
    struct entry *ptr = data->first;
    if(ptr == NULL) {
        data->first = node;
    }
    else {
        while(ptr->next != NULL && memcmp(ptr->pathname, node->pathname, node->namelen) < 0) {
            ptr = ptr->next;
        }

        /* searching by stage if equal */
        while(ptr->next != NULL
                && memcmp(ptr->pathname, node->pathname, node->namelen) == 0
                && (ptr->flags & 0x3000) < (node->flags & 0x3000)) {
            ptr = ptr->next;
        }
        node->next = ptr->next;
        ptr->next = node;
    }
    ++data->num;
    return AGC_SUCCESS;
}

int main(int argc, char **argv)
{
    if(argc < 2) {
        fputs("Usage: agc init/add filename", stderr);
        return AGC_NOT_ENOUGH_ARGS;
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

    }
    else if(strcmp(argv[1], "commit") == 0) {

    }
    else if(strcmp(argv[1], "hash-object") == 0) {
        struct stat st = {0};
        if(stat(argv[2], &st) == -1) {
            fputs("fatal: cannot find file", stderr);
            return AGC_FILE_NOT_FOUND;
        }
        if(argc < 3) {
            fputs("Usage: agc init/add filename", stderr);
            return AGC_NOT_ENOUGH_ARGS;
        }
        char *header = NULL;
        size_t headsize = 0;
        int headerr = getheader(argv[2], "blob ", &header, &headsize);
        if(headerr != 0)
            return headerr;

        char *hash = NULL;
        size_t hsize = 0;
        hash_object(argv[2], header, headsize, &hash, &hsize);

        // TODO: How to parse parameter?
//        int err = storefile(argv[2], header, headsize, hash);
        printf("%s\n", hash);

        free(header);
        free(hash);
        return AGC_SUCCESS;
    }
    // TODO: Make it write to stdout
    else if(strcmp(argv[1], "cat-file") == 0) {
        FILE* src = fopen(argv[2], "rb");
        FILE* dest = fopen("testdest", "wb");
        int ret = inf(src, dest);
        return ret;
    }
    else if(strcmp(argv[1], "update-index") == 0) {
        struct index data;
        enum agc_error err = read_index(&data);
        if(err != AGC_SUCCESS) {
            return err;
        }
        /* building new node */
        struct entry node;
        // TODO: initialize node and add to data store
        // Need to have its hash
        err = add_to_index(&data, &node);
        if(err != AGC_SUCCESS) {
            return err;
        }
        /* writing changes to file */
        err = write_index(&data);
        if(err != AGC_SUCCESS) {
            return err;
        }
    }
    else if(strcmp(argv[1], "write-tree") == 0) {

    }
    else if(strcmp(argv[1], "commit-tree") == 0) {

    }
    else {
        printf("Invalid command");
    }
    return 0;
}
