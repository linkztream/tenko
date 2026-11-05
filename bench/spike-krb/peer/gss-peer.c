/*
 * GSS-API initiator for the Kerberos spike: the MIT side of the exchange.
 *
 * Connects to the spike's acceptor over TCP, establishes a context with
 * gss_init_sec_context (mutual authentication, integrity, sequence and replay
 * detection), then exchanges one MIC token in each direction: it signs a message
 * with gss_get_mic and verifies the acceptor's MIC over the acceptor's message with
 * gss_verify_mic. Every frame on the wire is a 4-octet big-endian length followed
 * by the bytes.
 *
 * With --record <prefix> every token and the context key are written as hex files
 * so that they become fixtures of the spike's tests.
 *
 * Build: gcc -O2 -Wall -o gss-peer gss-peer.c -lgssapi_krb5
 */
#include <arpa/inet.h>
#include <errno.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static gss_OID_desc krb5_mech = {9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};
static gss_OID_desc ms_krb5_mech = {9, (void *)"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"};
static gss_OID_desc spnego_mech = {6, (void *)"\x2b\x06\x01\x05\x05\x02"};
/* GSS_C_INQ_SSPI_SESSION_KEY: 1.2.840.113554.1.2.2.5.5 */
static gss_OID_desc inq_session_key = {11, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"};

static void die(const char *what) {
    perror(what);
    exit(2);
}

static void gss_die(const char *what, OM_uint32 maj, OM_uint32 min, gss_OID mech) {
    OM_uint32 ctx = 0, mstat;
    gss_buffer_desc msg;
    fprintf(stderr, "%s failed: major 0x%x minor 0x%x\n", what, maj, min);
    do {
        gss_display_status(&mstat, maj, GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx, &msg);
        fprintf(stderr, "  %.*s\n", (int)msg.length, (char *)msg.value);
        gss_release_buffer(&mstat, &msg);
    } while (ctx != 0);
    ctx = 0;
    do {
        gss_display_status(&mstat, min, GSS_C_MECH_CODE, mech, &ctx, &msg);
        fprintf(stderr, "  %.*s\n", (int)msg.length, (char *)msg.value);
        gss_release_buffer(&mstat, &msg);
    } while (ctx != 0);
    exit(3);
}

static void send_frame(int fd, const void *data, size_t len) {
    uint32_t be = htonl((uint32_t)len);
    if (write(fd, &be, 4) != 4) die("write length");
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, (const char *)data + off, len - off);
        if (n <= 0) die("write frame");
        off += (size_t)n;
    }
}

static void read_exact(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, (char *)buf + off, len - off);
        if (n == 0) {
            fprintf(stderr, "peer closed the connection\n");
            exit(4);
        }
        if (n < 0) die("read");
        off += (size_t)n;
    }
}

static void recv_frame(int fd, gss_buffer_t out) {
    uint32_t be;
    read_exact(fd, &be, 4);
    out->length = ntohl(be);
    if (out->length > (1u << 20)) {
        fprintf(stderr, "frame too large\n");
        exit(4);
    }
    out->value = malloc(out->length ? out->length : 1);
    read_exact(fd, out->value, out->length);
}

static void record(const char *prefix, const char *name, const void *data, size_t len) {
    if (!prefix) return;
    char path[1024];
    snprintf(path, sizeof path, "%s.%s.hex", prefix, name);
    FILE *f = fopen(path, "w");
    if (!f) die(path);
    for (size_t i = 0; i < len; i++) fprintf(f, "%02x", ((const unsigned char *)data)[i]);
    fprintf(f, "\n");
    fclose(f);
}

int main(int argc, char **argv) {
    const char *mech_name = "spnego";
    const char *target = "DNS@tenko.corp.example.test";
    const char *host = "127.0.0.1";
    int port = 5353;
    const char *prefix = NULL;
    int mutual = 1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--mech") && i + 1 < argc) mech_name = argv[++i];
        else if (!strcmp(argv[i], "--target") && i + 1 < argc) target = argv[++i];
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--record") && i + 1 < argc) prefix = argv[++i];
        else if (!strcmp(argv[i], "--no-mutual")) mutual = 0;
        else {
            fprintf(stderr, "usage: gss-peer [--mech krb5|ms-krb5|spnego] [--target DNS@host] [--host h] [--port p] [--record prefix] [--no-mutual]\n");
            return 1;
        }
    }
    gss_OID mech;
    if (!strcmp(mech_name, "krb5")) mech = &krb5_mech;
    else if (!strcmp(mech_name, "ms-krb5")) mech = &ms_krb5_mech;
    else if (!strcmp(mech_name, "spnego")) mech = &spnego_mech;
    else {
        fprintf(stderr, "unknown mech %s\n", mech_name);
        return 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) die("inet_pton");
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) die("connect");

    OM_uint32 maj, min;
    gss_buffer_desc name_buf = {strlen(target), (void *)target};
    gss_name_t target_name;
    maj = gss_import_name(&min, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (GSS_ERROR(maj)) gss_die("gss_import_name", maj, min, mech);

    OM_uint32 req_flags = GSS_C_INTEG_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG;
    if (mutual) req_flags |= GSS_C_MUTUAL_FLAG;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in_tok = GSS_C_EMPTY_BUFFER, out_tok = GSS_C_EMPTY_BUFFER;
    gss_OID actual_mech = GSS_C_NO_OID;
    OM_uint32 ret_flags = 0;
    int step = 0;
    time_t started = time(NULL);
    for (;;) {
        maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx, target_name, mech, req_flags, 0,
                                   GSS_C_NO_CHANNEL_BINDINGS, &in_tok, &actual_mech, &out_tok, &ret_flags, NULL);
        if (GSS_ERROR(maj)) gss_die("gss_init_sec_context", maj, min, mech);
        if (in_tok.value) {
            free(in_tok.value);
            in_tok.value = NULL;
            in_tok.length = 0;
        }
        if (out_tok.length > 0) {
            char nm[32];
            snprintf(nm, sizeof nm, "init%d", step);
            record(prefix, nm, out_tok.value, out_tok.length);
            printf("initiator token %d: %zu octets\n", step, out_tok.length);
            send_frame(fd, out_tok.value, out_tok.length);
            gss_release_buffer(&min, &out_tok);
        }
        if (maj == GSS_S_COMPLETE) break;
        recv_frame(fd, &in_tok);
        char nm[32];
        snprintf(nm, sizeof nm, "accept%d", step);
        record(prefix, nm, in_tok.value, in_tok.length);
        printf("acceptor token %d: %zu octets\n", step, in_tok.length);
        step++;
        if (step > 8) {
            fprintf(stderr, "too many steps\n");
            return 5;
        }
    }
    printf("context established: flags 0x%x, mech %s\n", ret_flags, mech_name);

    gss_name_t src;
    gss_OID ctx_mech;
    OM_uint32 lifetime, flags2;
    int local, open;
    maj = gss_inquire_context(&min, ctx, &src, NULL, &lifetime, &ctx_mech, &flags2, &local, &open);
    if (!GSS_ERROR(maj)) {
        gss_buffer_desc disp;
        gss_display_name(&min, src, &disp, NULL);
        printf("initiator name: %.*s\n", (int)disp.length, (char *)disp.value);
        gss_release_buffer(&min, &disp);
        gss_release_name(&min, &src);
    }

    gss_buffer_set_t keyset = GSS_C_NO_BUFFER_SET;
    maj = gss_inquire_sec_context_by_oid(&min, ctx, &inq_session_key, &keyset);
    if (!GSS_ERROR(maj) && keyset && keyset->count >= 1) {
        record(prefix, "ctxkey", keyset->elements[0].value, keyset->elements[0].length);
        printf("context key: %zu octets", keyset->elements[0].length);
        if (keyset->count >= 2) {
            /* The second element is the enctype as a DER OID 1.2.840.113554.1.2.2.4.<etype>. */
            unsigned char *o = keyset->elements[1].value;
            printf(", enctype %u", o[keyset->elements[1].length - 1]);
        }
        printf("\n");
        gss_release_buffer_set(&min, &keyset);
    }

    const char *msg = "update tenko-spike IN A 192.0.2.10; signed by the initiator";
    gss_buffer_desc msg_buf = {strlen(msg), (void *)msg};
    gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
    maj = gss_get_mic(&min, ctx, GSS_C_QOP_DEFAULT, &msg_buf, &mic);
    if (GSS_ERROR(maj)) gss_die("gss_get_mic", maj, min, mech);
    record(prefix, "msg", msg, strlen(msg));
    record(prefix, "initmic", mic.value, mic.length);
    send_frame(fd, msg, strlen(msg));
    send_frame(fd, mic.value, mic.length);
    printf("initiator MIC sent: %zu octets\n", mic.length);
    gss_release_buffer(&min, &mic);

    gss_buffer_desc acc_msg, acc_mic;
    recv_frame(fd, &acc_msg);
    recv_frame(fd, &acc_mic);
    record(prefix, "accmsg", acc_msg.value, acc_msg.length);
    record(prefix, "accmic", acc_mic.value, acc_mic.length);
    gss_qop_t qop;
    maj = gss_verify_mic(&min, ctx, &acc_msg, &acc_mic, &qop);
    if (GSS_ERROR(maj)) gss_die("gss_verify_mic", maj, min, mech);
    /* Supplementary bits: 0x2 duplicate, 0x4 old, 0x8 unsequenced, 0x10 gap (RFC 2744). */
    printf("acceptor MIC verified over %zu octets: '%.*s' (major 0x%x, supplementary 0x%x)\n", acc_msg.length,
           (int)acc_msg.length, (char *)acc_msg.value, maj, GSS_SUPPLEMENTARY_INFO(maj));

    /* A second MIC, to show the sequence number moves. */
    const char *msg2 = "second message from the initiator";
    gss_buffer_desc msg2_buf = {strlen(msg2), (void *)msg2};
    maj = gss_get_mic(&min, ctx, GSS_C_QOP_DEFAULT, &msg2_buf, &mic);
    if (GSS_ERROR(maj)) gss_die("gss_get_mic 2", maj, min, mech);
    record(prefix, "msg2", msg2, strlen(msg2));
    record(prefix, "initmic2", mic.value, mic.length);
    send_frame(fd, msg2, strlen(msg2));
    send_frame(fd, mic.value, mic.length);
    gss_release_buffer(&min, &mic);
    gss_buffer_desc verdict;
    recv_frame(fd, &verdict);
    printf("acceptor verdict on the initiator MICs: %.*s\n", (int)verdict.length, (char *)verdict.value);
    if (prefix) {
        char path[1024];
        snprintf(path, sizeof path, "%s.meta.txt", prefix);
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "mech=%s\ntarget=%s\nmutual=%d\nflags=0x%x\nrecorded_unix=%ld\n", mech_name, target, mutual, ret_flags, (long)started);
            fclose(f);
        }
    }
    int ok = verdict.length == 2 && !memcmp(verdict.value, "OK", 2);
    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    close(fd);
    puts(ok ? "RESULT PASS" : "RESULT FAIL");
    return ok ? 0 : 6;
}
