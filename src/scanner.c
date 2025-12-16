#include "../include/guhya.h"

static pcre2_code *compiled[MAX_PATTERNS];
static char *compiled_names[MAX_PATTERNS];
static int pattern_count = 0;
static pthread_mutex_t secret_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct
{
    char *name;
    char *regex;
} pattern_def_t;

static const pattern_def_t patterns[] = {
    {"Generic Secret", "(?i)[\"']?access[_-]?key[_-]?secret[\"']?[^\\S\\r\\n]*[=:][^\\S\\r\\n]*[\"']?[\\w-]+[\"']?"},
    {"Generic Token", "(?i)[\"']?access[_-]?token[\"']?[^\\S\\r\\n]*[=:][^\\S\\r\\n]*[\"']?[\\w-]+[\"']?"},
    {"API Key", "(?i)[\"']?api[_-]?key[\"']?[^\\S\\r\\n]*[=:][^\\S\\r\\n]*[\"']?[\\w-]+[\"']?"},
    {"Client Secret", "(?i)[\"']?client[_-]?secret[\"']?[^\\S\\r\\n]*[=:][^\\S\\r\\n]*[\"']?[\\w-]+[\"']?"},
    {"AWS S3 Bucket", "(s3\\.amazonaws\\.com/|[a-zA-Z0-9_-]+\\.s3\\.amazonaws\\.com)"},
    {"Slack Token", "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"},
    {"OpenSSH Key", "-----BEGIN OPENSSH PRIVATE KEY-----(?:.|[\\r\\n])+-----END OPENSSH PRIVATE KEY-----"},
    {"Private Key", "-----BEGIN PRIVATE KEY-----[A-Za-z0-9\\s+/=]{100,}-----END PRIVATE KEY-----"},
    {"RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9\\s+/=]{100,}-----END RSA PRIVATE KEY-----"},
    {"Google Recaptcha", "6L[0-9A-Za-z-_]{38}"},
    {"Twilio SID", "AC[a-zA-Z0-9_-]{32}"},
    {"Google API", "AIza[0-9A-Za-z-_]{35}"},
    {"AWS Access Key", "AKIA[0-9A-Z]{16}"},
    {"Twilio Token", "AP[a-zA-Z0-9_-]{32}"},
    {"Basic Auth", "Basic [A-Za-z0-9+/]{15}"},
    {"Bearer Token", "Bearer\\s+[A-Za-z0-9_.-]{20,}"},
    {"AWS Cognito", "COGNITO_IDENTITY[A-Z0-9_]*:\\s*\"[^\"]+\""},
    {"Facebook Token", "EAACEdEose0cBA[0-9A-Za-z]+"},
    {"GitHub Token", "GITHUB_TOKEN[^\\S\\r\\n]*[=:][^\\S\\r\\n]*[\"']?[A-Za-z0-9_-]{36}[\"']?"},
    {"React Config", "REACT_APP_[A-Z_]+:\\s*\"([^\"]+)\""},
    {"SendGrid API", "SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}"},
    {"Twilio/Stripe", "SK[0-9a-fA-F]{32}"},
    {"Generic Token", "TOKEN=[A-Za-z0-9_.-]{20,}"},
    {"Google OAuth", "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"},
    {"Mailchimp API", "[0-9a-f]{32}-us[0-9]{1,2}"},
    {"Facebook Token", "[fF][aA][cC][eE][bB][oO][oO][kK].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]"},
    {"Heroku API", "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"},
    {"Twitter Token", "[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]"},
    {"PayPal Token", "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"},
    {"Amazon MWS", "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"},
    {"API Key", "api_key[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"']?[A-Za-z0-9_.-]{16,45}[\"']?"},
    {"AWS Session", "aws_session_token[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"']?AQo[A-Za-z0-9\\/+=]{100,}[\"']?"},
    {"Email", "client_email[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"'][^\"']+@[^\"']+[\"']"},
    {"Client Secret", "client_secret[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"']?[A-Za-z0-9_.-]{8,}[\"']?"},
    {"AWS Cognito ID", "com\\.amplify\\.Cognito\\.[a-z0-9-]+\\.([a-zA-Z0-9]+)\\.identityId"},
    {"Facebook Access", "facebook.*access_token[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"']?[A-Za-z0-9_.-]{10,}[\"']?"},
    {"GitHub OAuth", "gho_[A-Za-z0-9_]{36}"},
    {"GitHub Token", "ghp_[A-Za-z0-9_]{36}"},
    {"Slack Webhook", "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"},
    {"Generic Key", "key-[0-9a-zA-Z]{32}"},
    {"OAuth Token", "oauth[_-]?token[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"']?[A-Za-z0-9_.-]{8,}[\"']?"},
    {"Stripe Test", "pk_test_[0-9a-zA-Z]{24}"},
    {"Private Key", "private_key:\\s*-----BEGIN PRIVATE KEY-----"},
    {"Stripe Live", "rk_live_[0-9a-zA-Z]{24}"},
    {"Stripe Live", "sk_live_[0-9a-z]{32}"},
    {"Stripe Test", "sk_test_[0-9a-zA-Z]{24}"},
    {"SMTP Password", "smtp_pass[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"']?[^\\s\"']{8,}[\"']?"},
    {"Square Access", "sq0csp-[0-9A-Za-z\\-_]{43}"},
    {"Square OAuth", "sqOatp-[0-9A-Za-z\\-_]{22}"},
    {"SSH RSA Key", "ssh-rsa\\s+[A-Za-z0-9+/]{100,}"},
    {"Twitter Key", "twitter_consumer_key[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"']?[A-Za-z0-9]{20,}[\"']?"},
    {"API Key", "x-api-key[^\\S\\r\\n]*[:=][^\\S\\r\\n]*[\"']?[A-Za-z0-9_.-]{16,45}[\"']?"},
    {"Google OAuth", "ya29\\.[0-9A-Za-z\\-_]+"},
    {NULL, NULL}};

typedef struct secret
{
    char *val;
    struct secret *next;
} secret_t;
static secret_t *secrets = NULL;

static int seen_secret(const char *s)
{
    pthread_mutex_lock(&secret_lock);
    for (secret_t *n = secrets; n; n = n->next)
    {
        if (!strcmp(n->val, s))
        {
            pthread_mutex_unlock(&secret_lock);
            return 1;
        }
    }
    secret_t *n = malloc(sizeof(*n));
    if (n)
    {
        n->val = strdup(s);
        n->next = secrets;
        secrets = n;
    }
    pthread_mutex_unlock(&secret_lock);
    return 0;
}

static int get_line_number(const char *buf, size_t offset)
{
    int lines = 1;
    for (size_t i = 0; i < offset && buf[i]; i++)
    {
        if (buf[i] == '\n')
            lines++;
    }
    return lines;
}

void init_patterns(char *extra_pattern)
{
    int static_count = 0;
    while (patterns[static_count].regex)
        static_count++;

    int errnum;
    PCRE2_SIZE erroffset;

    for (int i = 0; i < static_count; i++)
    {
        pcre2_code *rc = pcre2_compile((PCRE2_SPTR)patterns[i].regex, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE, &errnum, &erroffset, NULL);
        if (rc)
        {
            pcre2_jit_compile(rc, PCRE2_JIT_COMPLETE);
            compiled[pattern_count] = rc;
            compiled_names[pattern_count] = strdup(patterns[i].name); /* Store the Name */
            pattern_count++;
        }
    }

    if (extra_pattern && strlen(extra_pattern) > 0)
    {
        pcre2_code *rc = pcre2_compile((PCRE2_SPTR)extra_pattern, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE, &errnum, &erroffset, NULL);
        if (rc)
        {
            pcre2_jit_compile(rc, PCRE2_JIT_COMPLETE);
            compiled[pattern_count] = rc;
            compiled_names[pattern_count] = strdup("Custom Pattern");
            pattern_count++;
        }
    }
}

void cleanup_patterns()
{
    for (int i = 0; i < pattern_count; i++)
    {
        pcre2_code_free(compiled[i]);
        free(compiled_names[i]);
    }

    secret_t *curr = secrets;
    while (curr)
    {
        secret_t *next = curr->next;
        free(curr->val);
        free(curr);
        curr = next;
    }
}

void match_and_report(const char *buf, size_t len, const char *source)
{
    for (int i = 0; i < pattern_count; i++)
    {
        pcre2_match_data *md = pcre2_match_data_create_from_pattern(compiled[i], NULL);
        if (!md)
            continue;

        PCRE2_SIZE start_offset = 0;
        int rc;

        while ((rc = pcre2_match(compiled[i], (PCRE2_SPTR)buf, len, start_offset, 0, md, NULL)) >= 0)
        {
            PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(md);
            if (ovector[0] == ovector[1])
            {
                if (ovector[0] >= len)
                    break;
                start_offset = ovector[1] + 1;
                continue;
            }

            size_t l = ovector[1] - ovector[0];
            char *hit = strndup(buf + ovector[0], l);

            if (hit && !seen_secret(hit))
            {
                pthread_mutex_lock(&print_lock);
                if (detailed)
                {
                    int lineno = get_line_number(buf, ovector[0]);
                    printf("[+] %s found in %s [Line: %d] [%s]\n", hit, source, lineno, compiled_names[i]);
                    if (out_fp)
                    {
                        fprintf(out_fp, "[+] %s found in %s [Line: %d] [%s]\n", hit, source, lineno, compiled_names[i]);
                        fflush(out_fp);
                    }
                }
                else
                {
                    printf("[+] %s [%s] [%s]\n", source, hit, compiled_names[i]);
                    if (out_fp)
                    {
                        fprintf(out_fp, "[+] %s [%s] [%s]\n", source, hit, compiled_names[i]);
                        fflush(out_fp);
                    }
                }
                pthread_mutex_unlock(&print_lock);
            }
            if (hit)
                free(hit);
            start_offset = ovector[1];
        }
        pcre2_match_data_free(md);
    }
}