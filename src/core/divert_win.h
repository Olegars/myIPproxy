#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define DIVERT_ADDR_BYTES 256

typedef struct DivertMeta {
    unsigned char addr[DIVERT_ADDR_BYTES];
    int outbound;
    int loopback;
    int ipv6;
    unsigned ifIdx;
    unsigned subIfIdx;
} DivertMeta;

#define DIVERT_LAYER_NETWORK 0
#define DIVERT_LAYER_SOCKET 3
#define DIVERT_FLAG_SNIFF 0x1
#define DIVERT_FLAG_RECV_ONLY 0x4

void *divert_load(const wchar_t *dllPath);
void divert_unload(void *library);
void *divert_open(void *library, const char *filter, int layer, unsigned long long flags, unsigned *error);
void divert_shutdown(void *library, void *handle);
void divert_close(void *library, void *handle);
int divert_recv(void *library, void *handle, unsigned char *buffer, unsigned capacity, unsigned *length, DivertMeta *meta);
int divert_send(void *library, void *handle, unsigned char *buffer, unsigned length, const DivertMeta *meta, int rewrite);
int divert_parse(void *library, unsigned char *buffer, unsigned length,
                 unsigned char **ip4, unsigned char **ip6, unsigned char **tcp, unsigned char **udp);
int divert_read_socket(const DivertMeta *meta, unsigned *event, unsigned *pid, unsigned *localPort,
                       unsigned *remotePort, unsigned *protocol);

#ifdef __cplusplus
}
#endif
