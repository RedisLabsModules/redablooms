/*
* redablooms - a Redis module port of the dablooms library 
* Copyright (C) 2016 Redis Labs
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* dablooms (https://github.com/bitly/dablooms) copyright notice:
* Copyright @2012 by Justin Hines at Bitly under a very liberal license. See
* LICENSE in the source distribution.
*
* 'ustime' and 'mstime' inlined from Redis.
* Redis (https://github.com/antirez/redis) copyright notice:
* Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*   * Redistributions of source code must retain the above copyright notice,
*     this list of conditions and the following disclaimer.
*   * Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the
*     documentation and/or other materials provided with the distribution.
*   * Neither the name of Redis nor the names of its contributors may be used
*     to endorse or promote products derived from this software without
*     specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/time.h>

#include "murmur.h"
#include "../redismodule.h"

#define REDIS_LOG(str) fprintf(stderr, "redablooms.so: %s\n", str);

#define DABLOOMS_VERSION "0.9.1"
#define ERROR_TIGHTENING_RATIO 0.5
#define SALT_CONSTANT 0x97c29b3a

#define SIGNATURE_MAX_LEN 16
#define COUNTING_BLOOM_FILTER_SIGNATURE "CBF.0.1"
#define SCALING_BLOOM_FILTER_SIGNATURE "SBF.0.1"

/* Filter defaults - need to be moved to config and read whenever creating a new
 * filter. */
#define CAPACITY 100000
#define ERROR_RATE .05

typedef struct {
  size_t bytes;
  RedisModuleKey *key;
  char *array;
} bitmap_t;

typedef struct {
  unsigned int capacity;
  unsigned int counts_per_func;
  size_t nfuncs;
  size_t size;
  size_t num_bytes;
  double error_rate;
  uint64_t id;
  uint32_t count;
} counting_bloom_header_t;

typedef struct {
  counting_bloom_header_t *header;
  long offset;
  uint32_t *hashes;
  bitmap_t *bitmap;
} counting_bloom_t;

typedef struct {
  unsigned int capacity;
  size_t num_bytes;
  double error_rate;
  uint64_t max_id;
} scaling_bloom_header_t;

typedef struct {
  unsigned int num_blooms;
  scaling_bloom_header_t *header;
  counting_bloom_t **blooms;
  bitmap_t *bitmap;
} scaling_bloom_t;

/* Return the UNIX time in microseconds */
long long ustime(void) {
  struct timeval tv;
  long long ust;

  gettimeofday(&tv, NULL);
  ust = ((long long)tv.tv_sec) * 1000000;
  ust += tv.tv_usec;
  return ust;
}

/* Return the UNIX time in milliseconds */
mstime_t mstime(void) {
    return ustime()/1000;
}

void free_bitmap(bitmap_t *bitmap) {
  RedisModule_CloseKey(bitmap->key);
  free(bitmap);
}

bitmap_t *bitmap_resize(bitmap_t *bitmap, size_t old_size, size_t new_size) {
  size_t size = RedisModule_ValueLength(bitmap->key);

  /* grow key if necessary */
  if (size < new_size) {
    if (RedisModule_StringTruncate(bitmap->key, new_size) != REDISMODULE_OK) {
      free_bitmap(bitmap);
      return NULL;
    }
  }

  bitmap->array = RedisModule_StringDMA(bitmap->key, &bitmap->bytes,
                                        REDISMODULE_READ | REDISMODULE_WRITE);
  return bitmap;
}

/* Create a new bitmap, not full featured, simple to give
 * us a means of interacting with the 4 bit counters */
bitmap_t *new_bitmap(RedisModuleKey *key, size_t bytes) {
  bitmap_t *bitmap;

  if ((bitmap = (bitmap_t *)malloc(sizeof(bitmap_t))) == NULL) {
    return NULL;
  }

  bitmap->bytes = bytes;
  bitmap->key = key;
  bitmap->array = NULL;

  if ((bitmap = bitmap_resize(bitmap, 0, bytes)) == NULL) {
    return NULL;
  }

  return bitmap;
}

/* increments the four bit counter */
int bitmap_increment(bitmap_t *bitmap, unsigned int index, long offset) {
  long access = index / 2 + offset;
  uint8_t temp;
  uint8_t n = bitmap->array[access];
  if (index % 2 != 0) {
    temp = (n & 0x0f);
    n = (n & 0xf0) + ((n & 0x0f) + 0x01);
  } else {
    temp = (n & 0xf0) >> 4;
    n = (n & 0x0f) + ((n & 0xf0) + 0x10);
  }

  if (temp == 0x0f) {
    REDIS_LOG("ERR 4 bit int Overflow")
    return -1;
  }

  bitmap->array[access] = n;
  return 0;
}

/* decrements the four bit counter */
int bitmap_decrement(bitmap_t *bitmap, unsigned int index, long offset) {
  long access = index / 2 + offset;
  uint8_t temp;
  uint8_t n = bitmap->array[access];

  if (index % 2 != 0) {
    temp = (n & 0x0f);
    n = (n & 0xf0) + ((n & 0x0f) - 0x01);
  } else {
    temp = (n & 0xf0) >> 4;
    n = (n & 0x0f) + ((n & 0xf0) - 0x10);
  }

  if (temp == 0x00) {
    REDIS_LOG("Error, Decrementing zero")
    return -1;
  }

  bitmap->array[access] = n;
  return 0;
}

/* checks the four bit counter */
int bitmap_check(bitmap_t *bitmap, unsigned int index, long offset) {
  long access = index / 2 + offset;
  if (index % 2 != 0) {
    return bitmap->array[access] & 0x0f;
  } else {
    return bitmap->array[access] & 0xf0;
  }
}

/*
 * Perform the actual hashing for `key`
 *
 * Only call the hash once to get a pair of initial values (h1 and
 * h2). Use these values to generate all hashes in a quick loop.
 *
 * See paper by Kirsch, Mitzenmacher [2006]
 * http://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf
 */
void hash_func(counting_bloom_t *bloom, const char *key, size_t key_len,
               uint32_t *hashes) {
  int i;
  uint32_t checksum[4];

  MurmurHash3_x64_128(key, key_len, SALT_CONSTANT, checksum);
  uint32_t h1 = checksum[0];
  uint32_t h2 = checksum[1];

  for (i = 0; i < bloom->header->nfuncs; i++) {
    hashes[i] = (h1 + i * h2) % bloom->header->counts_per_func;
  }
}

int free_counting_bloom(counting_bloom_t *bloom) {
  if (bloom != NULL) {
    free(bloom->hashes);
    bloom->hashes = NULL;
    free_bitmap(bloom->bitmap);
    free(bloom);
    bloom = NULL;
  }
  return 0;
}

counting_bloom_t *counting_bloom_init(unsigned int capacity, double error_rate,
                                      long offset) {
  counting_bloom_header_t *header;

  if ((header = malloc(sizeof(counting_bloom_header_t))) == NULL) {
    REDIS_LOG("ERR could not allocate a new counting bloom filter header")
    return NULL;
  }

  header->capacity = capacity;
  header->error_rate = error_rate;
  header->nfuncs = (int)ceil(log(1 / error_rate) / log(2));
  header->counts_per_func = (int)ceil(capacity * fabs(log(error_rate)) /
                                      (header->nfuncs * pow(log(2), 2)));
  header->size = header->nfuncs * header->counts_per_func;
  /* rounding-up integer divide by 2 of bloom->size */
  header->num_bytes =
      ((header->size + 1) / 2) + sizeof(counting_bloom_header_t);

  counting_bloom_t *bloom;
  if ((bloom = malloc(sizeof(counting_bloom_t))) == NULL) {
    free(header);
    REDIS_LOG("ERR could not allocate a new counting bloom filter")
    return NULL;
  }
  bloom->bitmap = NULL;
  bloom->header = header;
  bloom->offset = offset + sizeof(counting_bloom_header_t);
  bloom->hashes = calloc(header->nfuncs, sizeof(uint32_t));
  if (bloom->hashes == NULL) {
    free(header);
    free(bloom);
    REDIS_LOG("ERR could not allocate a new counting bloom filter hashes")
    return NULL;
  }

  return bloom;
}

counting_bloom_t *new_counting_bloom(unsigned int capacity, double error_rate,
                                     RedisModuleCtx *ctx,
                                     RedisModuleString *keyname) {
  RedisModuleKey *key =
      RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ | REDISMODULE_WRITE);

  if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_EMPTY) {
    RedisModule_ReplyWithError(ctx, "ERR key exists");
    return NULL;
  }

  counting_bloom_t *cur_bloom = counting_bloom_init(capacity, error_rate, 0);
  counting_bloom_header_t *tmp_header = cur_bloom->header;

  cur_bloom->bitmap = new_bitmap(key, cur_bloom->header->num_bytes);
  cur_bloom->header = (counting_bloom_header_t *)(cur_bloom->bitmap->array);
  memcpy(cur_bloom->header, tmp_header, sizeof(counting_bloom_header_t));
  free(tmp_header);
  return cur_bloom;
}

int counting_bloom_add(counting_bloom_t *bloom, const char *s, size_t len) {
  unsigned int index, i, offset;
  unsigned int *hashes = bloom->hashes;

  hash_func(bloom, s, len, hashes);

  for (i = 0; i < bloom->header->nfuncs; i++) {
    offset = i * bloom->header->counts_per_func;
    index = hashes[i] + offset;
    bitmap_increment(bloom->bitmap, index, bloom->offset);
  }
  bloom->header->count++;

  return 0;
}

int counting_bloom_remove(counting_bloom_t *bloom, const char *s, size_t len) {
  unsigned int index, i, offset;
  unsigned int *hashes = bloom->hashes;

  hash_func(bloom, s, len, hashes);

  for (i = 0; i < bloom->header->nfuncs; i++) {
    offset = i * bloom->header->counts_per_func;
    index = hashes[i] + offset;
    bitmap_decrement(bloom->bitmap, index, bloom->offset);
  }
  bloom->header->count--;

  return 0;
}

int counting_bloom_check(counting_bloom_t *bloom, const char *s, size_t len) {
  unsigned int index, i, offset;
  unsigned int *hashes = bloom->hashes;

  hash_func(bloom, s, len, hashes);

  for (i = 0; i < bloom->header->nfuncs; i++) {
    offset = i * bloom->header->counts_per_func;
    index = hashes[i] + offset;
    if (!(bitmap_check(bloom->bitmap, index, bloom->offset))) {
      return 0;
    }
  }
  return 1;
}

int free_scaling_bloom(scaling_bloom_t *bloom) {
  int i;
  for (i = bloom->num_blooms - 1; i >= 0; i--) {
    free(bloom->blooms[i]->hashes);
    bloom->blooms[i]->hashes = NULL;
    free(bloom->blooms[i]);
    bloom->blooms[i] = NULL;
  }
  free(bloom->blooms);
  free_bitmap(bloom->bitmap);
  free(bloom);
  return 0;
}

/* creates a new counting bloom filter from a given scaling bloom filter, with
 * count and id */
counting_bloom_t *new_counting_bloom_from_scale(scaling_bloom_t *bloom,
                                                int loading) {
  int i;
  long offset;
  double error_rate;
  counting_bloom_t *cur_bloom;

  error_rate = bloom->header->error_rate *
               (pow(ERROR_TIGHTENING_RATIO, bloom->num_blooms + 1));

  if ((bloom->blooms =
           realloc(bloom->blooms, (bloom->num_blooms + 1) *
                                      sizeof(counting_bloom_t *))) == NULL) {
    REDIS_LOG("ERR could not realloc new bloom filter")
    return NULL;
  }

  cur_bloom = counting_bloom_init(bloom->header->capacity, error_rate,
                                  bloom->header->num_bytes);
  if (cur_bloom == NULL) {
    REDIS_LOG("ERR could not initialize counting bloom filter")
    return NULL;
  }
  cur_bloom->bitmap = bloom->bitmap;
  counting_bloom_header_t *tmp_header = cur_bloom->header;
  bloom->blooms[bloom->num_blooms] = cur_bloom;
  bloom->num_blooms++;

  if (!loading) {
    bloom->bitmap =
        bitmap_resize(bloom->bitmap, bloom->header->num_bytes,
                      bloom->header->num_bytes + cur_bloom->header->num_bytes);
    if (bloom->bitmap == NULL) {
      REDIS_LOG("ERR could not resize bitmap")
      /* TODO: free cur_bloom and realloc blooms back? */
      return NULL;
    }

    /* reset header pointer, as StringDMA may have moved */
    bloom->header = (scaling_bloom_header_t *)bloom->bitmap->array;

    /* Set the pointers for these header structs to the right location since
     * mmap may have moved */
    for (i = 0; i < bloom->num_blooms; i++) {
      offset = bloom->blooms[i]->offset - sizeof(counting_bloom_header_t);
      bloom->blooms[i]->header =
          (counting_bloom_header_t *)(bloom->bitmap->array + offset);
    }

    /* Copy new bloom's header to bitmap */
    memcpy(bloom->blooms[bloom->num_blooms - 1]->header, tmp_header,
           sizeof(counting_bloom_header_t));
  } else {
    bloom->blooms[bloom->num_blooms - 1]->header =
        (counting_bloom_header_t *)(bloom->bitmap->array +
                                    bloom->blooms[bloom->num_blooms - 1]
                                        ->offset -
                                    sizeof(counting_bloom_header_t));
  }

  bloom->header->num_bytes += tmp_header->num_bytes;

  free(tmp_header);

  return bloom->blooms[bloom->num_blooms - 1];
}

counting_bloom_t *new_counting_bloom_from_key(RedisModuleCtx *ctx,
                                              RedisModuleString *keyname) {
  RedisModuleKey *key =
      RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ | REDISMODULE_WRITE);

  if (RedisModule_KeyType(key) == REDISMODULE_KEYTYPE_EMPTY) {
    RedisModule_ReplyWithError(ctx, "ERR key doesn't exist");
    return NULL;
  }

  /* TODO: add stricter type check. */
  if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
    RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
    return NULL;
  }

  size_t size = RedisModule_ValueLength(key);

  counting_bloom_t *bloom;
  if ((bloom = malloc(sizeof(counting_bloom_t))) == NULL) {
    RedisModule_ReplyWithError(ctx,
                               "ERR could not allocate counting bloom filter");
    REDIS_LOG("ERR could not allocate counting bloom filter")
    return NULL;
  }

  if ((bloom->bitmap = new_bitmap(key, size)) == NULL) {
    RedisModule_ReplyWithError(
        ctx, "ERR could not allocate counting bloom filter bitmap");
    REDIS_LOG("ERR could not allocate counting bloom filter bitmap")
    free(bloom);
    return NULL;
  }

  bloom->header = (counting_bloom_header_t *)(bloom->bitmap->array);

  bloom->offset = sizeof(counting_bloom_header_t);
  bloom->hashes = calloc(bloom->header->nfuncs, sizeof(uint32_t));
  if (bloom->hashes == NULL) {
    free_bitmap(bloom->bitmap);
    free(bloom);
    REDIS_LOG("ERR could not allocate a new counting bloom filter hashes")
    return NULL;
  }

  return bloom;
}

int scaling_bloom_add(scaling_bloom_t *bloom, const char *s, size_t len,
                      uint64_t id) {
  int i;

  counting_bloom_t *cur_bloom = NULL;
  for (i = bloom->num_blooms - 1; i >= 0; i--) {
    cur_bloom = bloom->blooms[i];
    if (id >= cur_bloom->header->id) {
      break;
    }
  }

  if ((id > bloom->header->max_id) &&
      (cur_bloom->header->count >= cur_bloom->header->capacity - 1)) {
    cur_bloom = new_counting_bloom_from_scale(bloom, 0);
    cur_bloom->header->count = 0;
    cur_bloom->header->id = bloom->header->max_id + 1;
  }
  if (bloom->header->max_id < id) {
    bloom->header->max_id = id;
  }
  counting_bloom_add(cur_bloom, s, len);

  return 1;
}

int scaling_bloom_remove(scaling_bloom_t *bloom, const char *s, size_t len,
                         uint64_t id) {
  counting_bloom_t *cur_bloom;
  int i;

  for (i = bloom->num_blooms - 1; i >= 0; i--) {
    cur_bloom = bloom->blooms[i];
    if (id >= cur_bloom->header->id) {
      counting_bloom_remove(cur_bloom, s, len);
      return 1;
    }
  }
  return 0;
}

int scaling_bloom_check(scaling_bloom_t *bloom, const char *s, size_t len) {
  int i;
  counting_bloom_t *cur_bloom;
  for (i = bloom->num_blooms - 1; i >= 0; i--) {
    cur_bloom = bloom->blooms[i];
    if (counting_bloom_check(cur_bloom, s, len)) {
      return 1;
    }
  }
  return 0;
}

scaling_bloom_t *scaling_bloom_init(unsigned int capacity, double error_rate,
                                    RedisModuleKey *key) {
  scaling_bloom_t *bloom;

  if ((bloom = malloc(sizeof(scaling_bloom_t))) == NULL) {
    return NULL;
  }
  bloom->num_blooms = 0;

  if ((bloom->bitmap = new_bitmap(key, sizeof(scaling_bloom_header_t))) ==
      NULL) {
    free_scaling_bloom(bloom);
    return NULL;
  }

  bloom->header = (scaling_bloom_header_t *)bloom->bitmap->array;
  bloom->header->capacity = capacity;
  bloom->header->error_rate = error_rate;
  bloom->header->num_bytes = sizeof(scaling_bloom_header_t);
  bloom->blooms = NULL;

  return bloom;
}

scaling_bloom_t *new_scaling_bloom(unsigned int capacity, double error_rate,
                                   RedisModuleCtx *ctx,
                                   RedisModuleString *keyname) {
  RedisModuleKey *key =
      RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ | REDISMODULE_WRITE);

  if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_EMPTY) {
    RedisModule_ReplyWithError(ctx, "ERR key exists");
    return NULL;
  }

  scaling_bloom_t *bloom;
  if (!(bloom = scaling_bloom_init(capacity, error_rate, key))) {
    RedisModule_CloseKey(key);
    RedisModule_ReplyWithError(ctx, "ERR could not create bitmap");
    REDIS_LOG("ERR could not create bitmap")
    return NULL;
  }

  counting_bloom_t *cur_bloom;
  if (!(cur_bloom = new_counting_bloom_from_scale(bloom, 0))) {
    RedisModule_ReplyWithError(ctx,
                               "ERR could not create counting bloom filter");
    REDIS_LOG("ERR could not create counting bloom filter")
    RedisModule_CloseKey(key);
    free_scaling_bloom(bloom);
    return NULL;
  }
  
  cur_bloom->header->id = 0;
  cur_bloom->header->count = 0;
  
  return bloom;
}

scaling_bloom_t *new_scaling_bloom_from_key(RedisModuleCtx *ctx,
                                            RedisModuleString *keyname) {
  RedisModuleKey *key =
      RedisModule_OpenKey(ctx, keyname, REDISMODULE_READ | REDISMODULE_WRITE);

  if (RedisModule_KeyType(key) == REDISMODULE_KEYTYPE_EMPTY) {
    RedisModule_ReplyWithError(ctx, "ERR key doesn't exist");
    return NULL;
  }

  /* TODO: add stricter type check. */
  if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_STRING) {
    RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
    return NULL;
  }

  size_t size = RedisModule_ValueLength(key);

  scaling_bloom_t *bloom;
  if ((bloom = malloc(sizeof(scaling_bloom_t))) == NULL) {
    RedisModule_ReplyWithError(ctx,
                               "ERR could not allocate scaling bloom filter");
    REDIS_LOG("ERR could not allocate scaling bloom filter")
    return NULL;
  }
  bloom->header = NULL;
  bloom->bitmap = NULL;
  bloom->blooms = NULL;
  bloom->num_blooms = 0;

  if ((bloom->bitmap = new_bitmap(key, size)) == NULL) {
    RedisModule_ReplyWithError(
        ctx, "ERR could not allocate scaling bloom filter bitmap");
    REDIS_LOG("ERR could not allocate scaling bloom filter bitmap")
    free(bloom);
    return NULL;
  }

  bloom->header = (scaling_bloom_header_t *)(bloom->bitmap->array);
  bloom->header->num_bytes = sizeof(scaling_bloom_header_t);
  size -= bloom->header->num_bytes;

  counting_bloom_t *cur_bloom;
  while (size) {
    cur_bloom = new_counting_bloom_from_scale(bloom, 1);
    // leave count and id as they were set in the file
    size -= cur_bloom->header->num_bytes;
  }
  return bloom;
}

/* CBF.INIT key capacity error */
int CBFInit_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                         int argc) {
  if (argc != 4) return RedisModule_WrongArity(ctx);

  long long capacity;
  if ((RedisModule_StringToLongLong(argv[2], &capacity) != REDISMODULE_OK) ||
      (capacity < 1) || (capacity > UINT_MAX))
    return RedisModule_ReplyWithError(ctx, "ERR capacity is totally wrong");

  double error_rate;
  if ((RedisModule_StringToDouble(argv[3], &error_rate) != REDISMODULE_OK) ||
      (error_rate < 0) || (error_rate > 1))
    return RedisModule_ReplyWithError(ctx, "ERR error rate is totally wrong");

  counting_bloom_t *bloom =
      new_counting_bloom((unsigned int)capacity, error_rate, ctx, argv[1]);
  if (bloom == NULL) return REDISMODULE_ERR;

  free_counting_bloom(bloom);

  RedisModule_ReplyWithSimpleString(ctx, "OK");
  return REDISMODULE_OK;
}

void CBFDebug_ReplyWithDump(RedisModuleCtx *ctx,
                            const counting_bloom_t *bloom) {
  RedisModule_ReplyWithArray(ctx, 11);

  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "sizeof(counting_bloom_header_t)");
  RedisModule_ReplyWithLongLong(ctx, sizeof(counting_bloom_header_t));
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "key ValueLength");
  RedisModule_ReplyWithLongLong(ctx,
                                RedisModule_ValueLength(bloom->bitmap->key));
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "num_bytes");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->num_bytes);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "offset");
  RedisModule_ReplyWithLongLong(ctx, bloom->offset);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "capacity");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->capacity);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "counts_per_func");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->counts_per_func);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "nfuncs");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->nfuncs);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "size");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->size);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "error_rate");
  RedisModule_ReplyWithDouble(ctx, bloom->header->error_rate);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "id");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->id);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "count");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->count);
}

/* CBF.DEBUG key */
int CBFDebug_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                          int argc) {
  if (argc != 2) return RedisModule_WrongArity(ctx);

  counting_bloom_t *bloom = new_counting_bloom_from_key(ctx, argv[1]);
  if (bloom == NULL) return REDISMODULE_ERR;

  CBFDebug_ReplyWithDump(ctx, bloom);

  free_counting_bloom(bloom);
  return REDISMODULE_OK;
}

/* CBF.ADD key elem [...]
 * TODO: specify optional capacity/error when creating -> how to handle
 * existing?
 * Reply: Integer, the number of elements in the filter. */
int CBFAdd_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                        int argc) {
  if (argc < 3) return RedisModule_WrongArity(ctx);

  RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
  unsigned type = RedisModule_KeyType(key);
  RedisModule_CloseKey(key);

  counting_bloom_t *bloom;

  if (type == REDISMODULE_KEYTYPE_EMPTY) {
    /* If the key is empty, initialize it using the defaults. */
    /* TODO: get from config. */
    bloom =
        new_counting_bloom((unsigned int)CAPACITY, ERROR_RATE, ctx, argv[1]);
  } else if (type == REDISMODULE_KEYTYPE_STRING) {
    bloom = new_counting_bloom_from_key(ctx, argv[1]);
  } else {
    return RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
  }
  if (bloom == NULL) return REDISMODULE_ERR;

  /* Add all elements to the filter. */
  size_t len;
  const char *ele;
  int i;
  for (i = 2; i < argc; i++) {
    ele = RedisModule_StringPtrLen(argv[i], &len);
    counting_bloom_add(bloom, ele, len);
  }

  RedisModule_ReplyWithLongLong(ctx, bloom->header->count);
  free_counting_bloom(bloom);

  return REDISMODULE_OK;
}

/* CBF.REM key elem [...]
 * Reply: Integer, the number of elements in the filter. */
int CBFRem_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                        int argc) {
  if (argc < 3) return RedisModule_WrongArity(ctx);

  RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
  unsigned type = RedisModule_KeyType(key);
  RedisModule_CloseKey(key);

  counting_bloom_t *bloom;

  if (type == REDISMODULE_KEYTYPE_EMPTY) {
    RedisModule_ReplyWithLongLong(ctx, 0);
    return REDISMODULE_OK;
  } else if (type == REDISMODULE_KEYTYPE_STRING) {
    bloom = new_counting_bloom_from_key(ctx, argv[1]);
  } else {
    return RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
  }
  if (bloom == NULL) return REDISMODULE_ERR;

  /* Remove elements from the filter. */
  size_t len;
  const char *ele;
  int i;
  for (i = 2; i < argc; i++) {
    ele = RedisModule_StringPtrLen(argv[i], &len);
    counting_bloom_remove(bloom, ele, len);
  }

  RedisModule_ReplyWithLongLong(ctx, bloom->header->count);
  free_counting_bloom(bloom);

  return REDISMODULE_OK;
}

/* CBF.CHECK key elem
 * Reply: Integer, 0 if not in filter, 1 if in (with  error_rate of false
 * positives. */
int CBFCheck_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                          int argc) {
  if (argc != 3) return RedisModule_WrongArity(ctx);

  RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
  unsigned type = RedisModule_KeyType(key);
  RedisModule_CloseKey(key);

  counting_bloom_t *bloom;

  if (type == REDISMODULE_KEYTYPE_EMPTY) {
    RedisModule_ReplyWithLongLong(ctx, 0);
    return REDISMODULE_OK;
  } else if (type == REDISMODULE_KEYTYPE_STRING) {
    bloom = new_counting_bloom_from_key(ctx, argv[1]);
  } else {
    return RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
  }
  if (bloom == NULL) return REDISMODULE_ERR;

  /* Check if element is in the filter. */
  size_t len;
  const char *ele = RedisModule_StringPtrLen(argv[2], &len);
  unsigned check = counting_bloom_check(bloom, ele, len);

  RedisModule_ReplyWithLongLong(ctx, check);
  free_counting_bloom(bloom);

  return REDISMODULE_OK;
}

/* SBF.INIT key capacity error */
int SBFInit_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                         int argc) {
  if (argc != 4) return RedisModule_WrongArity(ctx);

  long long capacity;
  if ((RedisModule_StringToLongLong(argv[2], &capacity) != REDISMODULE_OK) ||
      (capacity < 1) || (capacity > UINT_MAX))
    return RedisModule_ReplyWithError(ctx, "ERR capacity is totally wrong");

  double error_rate;
  if ((RedisModule_StringToDouble(argv[3], &error_rate) != REDISMODULE_OK) ||
      (error_rate < 0) || (error_rate > 1))
    return RedisModule_ReplyWithError(ctx, "ERR error rate is totally wrong ");

  scaling_bloom_t *bloom =
      new_scaling_bloom((unsigned int)capacity, error_rate, ctx, argv[1]);
  if (bloom == NULL) return REDISMODULE_ERR;

  free_scaling_bloom(bloom);

  RedisModule_ReplyWithSimpleString(ctx, "OK");
  return REDISMODULE_OK;
}

/* SBF.DEBUG key */
int SBFDebug_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                          int argc) {
  if (argc != 2) return RedisModule_WrongArity(ctx);

  scaling_bloom_t *bloom = new_scaling_bloom_from_key(ctx, argv[1]);
  if (bloom == NULL) return REDISMODULE_ERR;

  RedisModule_ReplyWithArray(ctx, 7);

  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "sizeof(scaling_bloom_t)");
  RedisModule_ReplyWithLongLong(ctx, sizeof(scaling_bloom_t));
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "key ValueLength");
  RedisModule_ReplyWithLongLong(ctx,
                                RedisModule_ValueLength(bloom->bitmap->key));
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "num_bytes");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->num_bytes);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "error_rate");
  RedisModule_ReplyWithDouble(ctx, bloom->header->error_rate);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "max_id");
  RedisModule_ReplyWithLongLong(ctx, bloom->header->max_id);
  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "num_blooms");
  RedisModule_ReplyWithLongLong(ctx, bloom->num_blooms);

  RedisModule_ReplyWithArray(ctx, 3);
  RedisModule_ReplyWithSimpleString(ctx, "blooms");
  RedisModule_ReplyWithLongLong(ctx, bloom->num_blooms);
  RedisModule_ReplyWithArray(ctx, bloom->num_blooms);

  int i;
  for (i = 0; i < bloom->num_blooms; i++)
    CBFDebug_ReplyWithDump(ctx, bloom->blooms[i]);

  free_scaling_bloom(bloom);
  return REDISMODULE_OK;
}

/* SBF.ADD key elem id [elem id ...]
 * SBF.REM key elem id [elem id ...]
 * When adding, id is always an integer, but it can be provided in several ways:
 *   - An unsigned integer 'n' means the literal numeric id 'n'.
 *   - '+[n]' means incrementing the current max_id by 'n'. 'n' is by default 1
 * (and if 0, then max_id isn't increased).
 *   - '/[n]' means the server's clock in msec, divided by 'n', floored and
 * multiplied by 'n'. 'n' is by default 1, 0 errors.
 * When removing, id must be either 'n', '/n' or '+0'.
 * Notes about adding multiple elements:
 *   - Clock is sampled once
 *   - ids are checked in advance for errors
 *   - once the max_id had changed, it can not be changed again and show error
 * on an attempt to do so.
 *   - an error does not change the filter
 * TODO: specify optional capacity/error when creating -> how to handle
 * existing?
 * Reply: Integer:
 *   - ADD: maxid.
 *   - REM: number of removals. */
int SBFOp_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                       int argc) {
  if ((argc < 4) || (argc % 2 != 0)) return RedisModule_WrongArity(ctx);

  /* Identify operation type */
  enum SBFOp_e { add, rem } op;
  int (*opfunc)(scaling_bloom_t *bloom, const char *s, size_t len, uint64_t id);
  size_t clen;
  const char *cmd = RedisModule_StringPtrLen(argv[0], &clen);
  if (!strncasecmp(cmd, "sbf.add", clen)) {
    op = add;
    opfunc = scaling_bloom_add;
  } else {
    op = rem;
    opfunc = scaling_bloom_remove;
  }

  scaling_bloom_t *bloom;
  RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
  unsigned type = RedisModule_KeyType(key);
  RedisModule_CloseKey(key);

  if (type == REDISMODULE_KEYTYPE_EMPTY) {
    if (op == add) {
      /* If the key is empty, initialize it using the defaults. */
      /* TODO: get from config. */
      bloom =
          new_scaling_bloom((unsigned int)CAPACITY, ERROR_RATE, ctx, argv[1]);
    } else {
      RedisModule_ReplyWithLongLong(ctx, 0);
      return REDISMODULE_OK;
    }
  } else if (type == REDISMODULE_KEYTYPE_STRING) {
    bloom = new_scaling_bloom_from_key(ctx, argv[1]);
  } else {
    return RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
  }
  if (bloom == NULL) return REDISMODULE_ERR;

  /* Prepare the ids. */
  unsigned num = (argc - 2) / 2;
  uint64_t *ids = calloc(num, sizeof(uint64_t));
  if (ids == NULL) {
    free_scaling_bloom(bloom);
    REDIS_LOG("ERR could not allocate ids")
    return RedisModule_ReplyWithError(ctx, "ERR could not allocate ids");
  }

  size_t idlen;
  const char *id;
  char *idend;
  long long time = mstime();
  unsigned max_updates = 0;
  unsigned i;
  for (i = 0; i < num; i++) {
    id = RedisModule_StringPtrLen(argv[i * 2 + 3], &idlen);
    if (idlen < 1) goto id_error;

    if (isdigit(id[0])) { /* the 'n' id. */
      errno = 0;
      ids[i] = strtoll(id, &idend, 10);
      if ((errno == ERANGE && (ids[i] == LONG_MAX || ids[i] == LONG_MIN)) ||
          (errno != 0 && ids[i] == 0)) {
        goto id_error;
      }
    } else if (id[0] == '+') { /* the '+n' id. */
      if (idlen != 1) {
        errno = 0;
        ids[i] = strtoll(&id[1], &idend, 10);
        if ((errno == ERANGE && (ids[i] == LONG_MAX || ids[i] == LONG_MIN)) ||
            (errno != 0 && ids[i] == 0) || (idend == &id[1]) ||
            (op == rem && ids[i] != 0)) {
          goto id_error;
        }
      } else {
        ids[i] = 1;
      }
      ids[i] += bloom->header->max_id;
    } else if (id[0] == '/') { /* the '/n' id. */
      if (idlen != 1) {
        errno = 0;
        ids[i] = strtoll(&id[1], &idend, 10);
        if ((errno == ERANGE && (ids[i] == LONG_MAX || ids[i] == LONG_MIN)) ||
            (ids[i] == 0) || (idend == &id[1])) {
          goto id_error;
        }
      } else {
        ids[i] = 1;
      }
      ids[i] = floor(time / ids[i]) * ids[i];
    } else
      goto id_error;

    max_updates += (ids[i] > bloom->header->max_id);
    if (max_updates > 1) goto id_error;

    continue;

  id_error:
    free(ids);
    free_scaling_bloom(bloom);
    char buff[4096];
    sprintf(buff, "ERR id '%s' %s", id,
            max_updates > 1 ? "results in too many maxid increments"
                            : "format is unknown");
    return RedisModule_ReplyWithError(ctx, buff);
  }

  size_t elen;
  const char *ele;
  long long opcount = 0;
  for (i = 0; i < num; i++) {
    ele = RedisModule_StringPtrLen(argv[2 + i * 2], &elen);
    opcount += opfunc(bloom, ele, elen, ids[i]);
  }

  RedisModule_ReplyWithLongLong(ctx,
                                op == add ? bloom->header->max_id : opcount);
  free(ids);
  free_scaling_bloom(bloom);

  return REDISMODULE_OK;
}

/* SBF.CHECK key elem
 * Checks if an element is in the filter.
 * Reply: Integer, 0 if not in filter, 1 if in (with  error_rate of false
 * positives. */
int SBFCheck_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                          int argc) {
  if (argc != 3) return RedisModule_WrongArity(ctx);

  RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
  unsigned type = RedisModule_KeyType(key);
  RedisModule_CloseKey(key);

  scaling_bloom_t *bloom;

  if (type == REDISMODULE_KEYTYPE_EMPTY) {
    RedisModule_ReplyWithLongLong(ctx, 0);
    return REDISMODULE_OK;
  } else if (type == REDISMODULE_KEYTYPE_STRING) {
    bloom = new_scaling_bloom_from_key(ctx, argv[1]);
  } else {
    return RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
  }
  if (bloom == NULL) return REDISMODULE_ERR;

  /* Check if element is in the filter. */
  size_t len;
  const char *ele = RedisModule_StringPtrLen(argv[2], &len);
  unsigned check = scaling_bloom_check(bloom, ele, len);

  RedisModule_ReplyWithLongLong(ctx, check);
  free_scaling_bloom(bloom);

  return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx) {
  if (RedisModule_Init(ctx, "redablooms", 1, REDISMODULE_APIVER_1) ==
      REDISMODULE_ERR)
    return REDISMODULE_ERR;

  /* CBF commands are internal/testing only */
  if (RedisModule_CreateCommand(ctx, "cbf.init", CBFInit_RedisCommand,
                                "write fast deny-oom", 1, 1,
                                1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "cbf.debug", CBFDebug_RedisCommand,
                                "readonly fast", 1, 1, 1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "cbf.add", CBFAdd_RedisCommand,
                                "write fast deny-oom", 1, 1,
                                1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "cbf.rem", CBFRem_RedisCommand,
                                "write fast", 1, 1, 1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "cbf.check", CBFCheck_RedisCommand,
                                "readonly fast", 1, 1, 1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "sbf.init", SBFInit_RedisCommand,
                                "write fast deny-oom", 1, 1,
                                1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "sbf.debug", SBFDebug_RedisCommand,
                                "readonly fast", 1, 1, 1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "sbf.add", SBFOp_RedisCommand,
                                "write fast deny-oom", 1, 1,
                                1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "sbf.rem", SBFOp_RedisCommand,
                                "write fast", 1, 1, 1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  if (RedisModule_CreateCommand(ctx, "sbf.check", SBFCheck_RedisCommand,
                                "readonly fast", 1, 1, 1) == REDISMODULE_ERR)
    return REDISMODULE_ERR;

  return REDISMODULE_OK;
}
