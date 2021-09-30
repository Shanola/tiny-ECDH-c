/* 
 * Alice is playing a server role, that can connect to multiple clients
 * For each connection, there're two mainly process: handshake and communication.
 * In the handshake process, server will verify the client's identity and exchange the public key, then compute the session key.
 * In the communication process, both side will encrypt sending data with the shared session key.
 * Stage 1: Single connecttion
 * Stage 2: Multiple connection
 */


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ecdh.h"

#define LISTENQ 1024
#define PORT 50000

typedef struct {
    uint32_t a, b, c, d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
    return (x << k) | (x >> (32 - k));
}

static uint32_t prng_next()
{
    uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);
    prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
    prng_ctx.b = prng_ctx.c + prng_ctx.d;
    prng_ctx.c = prng_ctx.d + e;
    prng_ctx.d = e + prng_ctx.a;
    return prng_ctx.d;
}

static void prng_init(uint32_t seed)
{
  uint32_t i;
  prng_ctx.a = 0xf1ea5eed;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

  for (i = 0; i < 31; ++i)
  {
    (void) prng_next();
  }
}

static int open_listenfd(int port)
{
    int listenfd, optval = 1;

    /* socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int)) < 0) {
    	return -1;
    }

    struct sockaddr_in serveraddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons((unsigned short) port),
        .sin_zero = {0},
    };
    
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
	perror("bind");
        return -1;
    }

    if (listen(listenfd, LISTENQ) < 0) {
        return -1;
    }

    return listenfd;
}


int main()
{
    int listenfd = open_listenfd(PORT);
    printf("Alice server start\n");

    struct sockaddr_in clientaddr;
    socklen_t inlen = 1;
    
    /* Accept a connection*/
    int infd = accept(listenfd, (struct sockaddr *) &clientaddr, &inlen);
    if (infd < 0) {
        return -1;
    }

    prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
    
    /* Generate a private key */
    static uint8_t prvkey[ECC_PRV_KEY_SIZE];
    for (int i = 0; i < ECC_PRV_KEY_SIZE; i++) {
        prvkey[i] = prng_next();
    }

    /* Generate a public key */
    static uint8_t pubkey[ECC_PUB_KEY_SIZE];
    assert(ecdh_generate_keys(pubkey, prvkey));
    printf("Alice private key: ");
    for (int i=0; i<ECC_PRV_KEY_SIZE; i++) {
        printf("%d ", prvkey[i]);
    }
    printf("\n");

    printf("Alice public key: ");
    for (int i=0; i<ECC_PUB_KEY_SIZE; i++) {
        printf("%d ", pubkey[i]);
    }
    printf("\n");

    /* Handshake Process*/
    uint8_t buf[ECC_PUB_KEY_SIZE];

    /* TODO: Verify identity */

    /* Wait for client public key */
    read(infd, buf, sizeof(buf));
    printf("Received client public key: ");
    for (int i=0; i<ECC_PUB_KEY_SIZE; i++) {
        printf("%d ", buf[i]);
    }
    printf("\n");

    /* TODO: Validation */

    /* Send alice public key */
    write(infd, pubkey, sizeof(pubkey));

    /* Compute and print shared secret */
    static uint8_t seckey[ECC_PUB_KEY_SIZE];
    assert(ecdh_shared_secret(prvkey, buf, seckey));
    printf("Shared secret is: ");
    for (int i=0; i<ECC_PUB_KEY_SIZE; i++) {
        printf("%d ", seckey[i]);
    }
    printf("\n");


    return 0;
}

