#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include "ecdh.c"

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


int main(int argc , char *argv[])
{

    //socket的建立
    int sockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if (sockfd == -1){
        printf("Fail to create a socket.");
    }

    //socket的連線

    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = PF_INET;

    //localhost test
    info.sin_addr.s_addr = inet_addr("127.0.0.1");
    info.sin_port = htons(50000);


    int err = connect(sockfd,(struct sockaddr *)&info,sizeof(info));
    if(err==-1){
        printf("Connection error");
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
    printf("Bob private key: ");
    for (int i=0; i<ECC_PRV_KEY_SIZE; i++) {
        printf("%d ", prvkey[i]);
    }
    printf("\n");

    printf("Bob public key: ");
    for (int i=0; i<ECC_PUB_KEY_SIZE; i++) {
        printf("%d ", pubkey[i]);
    }
    printf("\n");

    /* Handshake Process*/
    uint8_t buf[256];

    /* TODO: Verify identity */

    /* Send Bob public key */
    write(sockfd, pubkey, sizeof(pubkey));

    /* Wait for server public key */
    read(sockfd, buf, sizeof(buf));
    printf("Received server public key: ");
    for (int i=0; i<ECC_PUB_KEY_SIZE; i++) {
        printf("%d ", buf[i]);
    }
    printf("\n");

    /* TODO: Validation */

    /* Compute and print shared secret */
    static uint8_t seckey[ECC_PUB_KEY_SIZE];
    assert(ecdh_shared_secret(prvkey, buf, seckey));
    printf("Shared secret is: ");
    for (int i=0; i<ECC_PUB_KEY_SIZE; i++) {
        printf("%d ", seckey[i]);
    }
    printf("\n");

    printf("close Socket\n");
    close(sockfd);
    return 0;
}
