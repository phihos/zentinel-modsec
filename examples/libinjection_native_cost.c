/* Native C control for examples/libinjection_cost.rs, built with the same
 * upstream source and without LTO. See vendor/libinjection/README.md. */
#define _POSIX_C_SOURCE 200809L
#include "libinjection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
    size_t n = argc > 1 ? strtoul(argv[1], NULL, 10) : 1000000;
    const char *inputs[] = {"/update-assets", "-1839\" or \"1\"=\"2", "hello world", "<img src=x onerror=alert(1)>"};
    const char *names[] = {"sqli-safe", "sqli-attack", "xss-safe", "xss-attack"};
    for (size_t c = 0; c < 4; ++c) {
        size_t len = strlen(inputs[c]);
        volatile size_t hits = 0;
        struct timespec begin, end;
        clock_gettime(CLOCK_MONOTONIC, &begin);
        for (size_t i = 0; i < n; ++i) {
            char fingerprint[8] = {0};
            hits += (c < 2 ? libinjection_sqli(inputs[c], len, fingerprint) : libinjection_xss(inputs[c], len)) != 0;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double ns = (end.tv_sec-begin.tv_sec)*1e9 + end.tv_nsec-begin.tv_nsec;
        printf("case=%s backend=native-c n=%zu hits=%zu ns_per_eval=%.2f\n", names[c], n, hits, ns/n);
    }
}
