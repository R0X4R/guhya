#ifndef GUHYA_H
#define GUHYA_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#define MAX_PATTERNS 4096
#define MAX_URLS 200000
#define BUF_SZ 5242880

typedef struct
{
    char *buf;
    size_t len;
} mem_t;

typedef struct
{
    char **urls;
    int count;
    int idx;
    pthread_mutex_t lock;
} queue_t;

extern int thread_count;
extern int silent;
extern int detailed;
extern char *ua;
extern char *cookie;
extern char *input_label;
extern char *output_file;
extern FILE *out_fp;
extern pthread_mutex_t print_lock;

void banner();
void init_patterns(char *extra_pattern);
void cleanup_patterns();
void match_and_report(const char *buf, size_t len, const char *source);
void *worker(void *arg);

#endif