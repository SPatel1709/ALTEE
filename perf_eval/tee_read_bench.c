#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct request {
        char *path;
        int expected_allow;
};

static uint64_t now_ns(void)
{
        struct timespec time;

        if (clock_gettime(CLOCK_MONOTONIC_RAW, &time) != 0) {
                perror("clock_gettime");
                exit(1);
        }
        return (uint64_t)time.tv_sec * 1000000000ULL + time.tv_nsec;
}

static int compare_u64(const void *left, const void *right)
{
        uint64_t a = *(const uint64_t *)left;
        uint64_t b = *(const uint64_t *)right;
        return (a > b) - (a < b);
}

static uint64_t percentile(const uint64_t *sorted, size_t count, unsigned percent)
{
        size_t rank = ((size_t)percent * count + 99) / 100;
        return sorted[rank - 1];
}

static int read_once(const struct request *request)
{
        char byte;
        int fd = open(request->path, O_RDONLY | O_CLOEXEC);
        ssize_t bytes;

        if (fd < 0) {
                if (errno == EACCES || errno == EPERM)
                        return 0;
                perror(request->path);
                exit(1);
        }

        bytes = read(fd, &byte, 1);
        if (bytes < 0) {
                int error = errno;
                close(fd);
                if (error == EACCES || error == EPERM)
                        return 0;
                errno = error;
                perror(request->path);
                exit(1);
        }
        if (close(fd) != 0) {
                perror("close");
                exit(1);
        }
        return 1;
}

static struct request *read_workload(const char *path, size_t *count)
{
        struct request *requests = NULL;
        char *line = NULL;
        size_t line_size = 0;
        size_t capacity = 0;
        ssize_t length;
        FILE *file = fopen(path, "r");

        if (!file) {
                perror(path);
                exit(1);
        }
        *count = 0;
        while ((length = getline(&line, &line_size, file)) != -1) {
                char *space = strchr(line, ' ');
                char *filename;
                int expected_allow;

                if (!space || !((space - line == 5 && memcmp(line, "ALLOW", 5) == 0) ||
                                (space - line == 4 && memcmp(line, "DENY", 4) == 0))) {
                        fprintf(stderr, "Invalid workload line: %s", line);
                        exit(1);
                }
                expected_allow = space - line == 5;
                filename = space + 1;
                filename[strcspn(filename, "\r\n")] = 0;
                if (filename[0] != '/' || !filename[1]) {
                        fprintf(stderr, "Invalid object path: %s\n", filename);
                        exit(1);
                }
                if (*count == capacity) {
                        struct request *grown;
                        capacity = capacity ? capacity * 2 : 16;
                        grown = realloc(requests, capacity * sizeof(*requests));
                        if (!grown) {
                                perror("realloc");
                                exit(1);
                        }
                        requests = grown;
                }
                requests[*count].path = strdup(filename);
                requests[*count].expected_allow = expected_allow;
                if (!requests[*count].path) {
                        perror("strdup");
                        exit(1);
                }
                (*count)++;
        }
        if (ferror(file)) {
                perror(path);
                exit(1);
        }
        free(line);
        fclose(file);
        if (!*count) {
                fprintf(stderr, "Empty workload: %s\n", path);
                exit(1);
        }
        return requests;
}

static size_t parse_count(const char *text)
{
        char *end;
        unsigned long long value;

        errno = 0;
        value = strtoull(text, &end, 10);
        if (errno || !*text || *end || !value || value > SIZE_MAX) {
                fprintf(stderr, "Invalid iteration count: %s\n", text);
                exit(1);
        }
        return (size_t)value;
}

int main(int argc, char **argv)
{
        struct request *requests;
        uint64_t *latencies;
        uint64_t sum = 0;
        uint64_t started, finished;
        size_t count, iterations, warmup, i;
        size_t allows = 0, denies = 0;
        FILE *output;

        if (argc != 6) {
                fprintf(stderr, "Usage: %s WORKLOAD ITERATIONS WARMUP LABEL RESULTS.csv\n", argv[0]);
                return 2;
        }
        iterations = parse_count(argv[2]);
        warmup = strcmp(argv[3], "0") == 0 ? 0 : parse_count(argv[3]);
        requests = read_workload(argv[1], &count);
        latencies = malloc(iterations * sizeof(*latencies));
        if (!latencies) {
                perror("malloc");
                return 1;
        }

        for (i = 0; i < warmup; i++) {
                const struct request *request = &requests[i % count];
                if (read_once(request) != request->expected_allow) {
                        fprintf(stderr, "Warmup decision mismatch: %s\n", request->path);
                        return 1;
                }
        }

        started = now_ns();
        for (i = 0; i < iterations; i++) {
                const struct request *request = &requests[i % count];
                uint64_t before = now_ns();
                int allowed = read_once(request);
                uint64_t after = now_ns();

                if (allowed != request->expected_allow) {
                        fprintf(stderr, "Decision mismatch on request %zu: %s\n", i, request->path);
                        return 1;
                }
                if (allowed)
                        allows++;
                else
                        denies++;
                latencies[i] = after - before;
                sum += latencies[i];
        }
        finished = now_ns();

        qsort(latencies, iterations, sizeof(*latencies), compare_u64);
        output = fopen(argv[5], "w");
        if (!output) {
                perror(argv[5]);
                return 1;
        }
        fprintf(output, "label,samples,allows,denies,mean_ns,p50_ns,p95_ns,p99_ns,ops_per_sec\n");
        fprintf(output, "%s,%zu,%zu,%zu,%.1f,%llu,%llu,%llu,%.1f\n", argv[4], iterations,
                allows, denies, (double)sum / iterations,
                (unsigned long long)percentile(latencies, iterations, 50),
                (unsigned long long)percentile(latencies, iterations, 95),
                (unsigned long long)percentile(latencies, iterations, 99),
                (double)iterations * 1e9 / (finished - started));
        fclose(output);
        printf("%s: %zu reads, %zu allowed, %zu denied, %.1f ops/s; %s\n", argv[4],
               iterations, allows, denies, (double)iterations * 1e9 / (finished - started), argv[5]);
        for (i = 0; i < count; i++)
                free(requests[i].path);
        free(requests);
        free(latencies);
        return 0;
}
