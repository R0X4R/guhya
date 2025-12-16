#include "../include/guhya.h"

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *u)
{
    mem_t *m = u;
    size_t n = size * nmemb;
    if (m->len + n >= BUF_SZ)
        return 0;
    memcpy(m->buf + m->len, ptr, n);
    m->len += n;
    m->buf[m->len] = 0;
    return n;
}

static void process_url(CURL *c, const char *url)
{
    if (!c)
        return;

    pthread_mutex_lock(&print_lock);
    if (!silent && detailed)
        printf("[*] Scanning: %s\n", url);
    pthread_mutex_unlock(&print_lock);

    mem_t mem = {calloc(1, BUF_SZ), 0};
    if (!mem.buf)
        return;

    curl_easy_reset(c);
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, ua);
    if (cookie && strlen(cookie) > 0)
        curl_easy_setopt(c, CURLOPT_COOKIE, cookie);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &mem);

    CURLcode res = curl_easy_perform(c);

    if (res == CURLE_OK)
    {
        match_and_report(mem.buf, mem.len, url);
    }
    else
    {
        pthread_mutex_lock(&print_lock);
        if (!silent && detailed)
            fprintf(stderr, "[!] Error fetching %s: %s\n", url, curl_easy_strerror(res));
        pthread_mutex_unlock(&print_lock);
    }
    free(mem.buf);
}

void *worker(void *arg)
{
    queue_t *q = arg;
    CURL *curl = curl_easy_init();
    if (!curl)
        return NULL;

    while (1)
    {
        char *u = NULL;
        pthread_mutex_lock(&q->lock);
        if (q->idx < q->count)
            u = q->urls[q->idx++];
        pthread_mutex_unlock(&q->lock);

        if (!u)
            break;

        if (access(u, F_OK) == 0)
        {
            FILE *f = fopen(u, "rb");
            if (f)
            {
                mem_t mem = {calloc(1, BUF_SZ), 0};
                if (mem.buf)
                {
                    size_t n;
                    while ((n = fread(mem.buf + mem.len, 1, BUF_SZ - mem.len - 1, f)) > 0)
                    {
                        mem.len += n;
                        if (mem.len >= BUF_SZ - 1)
                            break;
                    }
                    mem.buf[mem.len] = 0;
                    match_and_report(mem.buf, mem.len, u);
                    free(mem.buf);
                }
                fclose(f);
            }
        }
        else
        {
            process_url(curl, u);
        }
    }
    curl_easy_cleanup(curl);
    return NULL;
}