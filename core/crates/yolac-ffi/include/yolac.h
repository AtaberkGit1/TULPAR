#ifndef YOLAC_H
#define YOLAC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum YolacProfile {
    YOLAC_PROFILE_STANDARD = 0,
    YOLAC_PROFILE_LOW_MEMORY_IOS = 1,
} YolacProfile;

typedef enum YolacState {
    YOLAC_STATE_INACTIVE = 0,
    YOLAC_STATE_ACTIVATING = 1,
    YOLAC_STATE_ACTIVE = 2,
    YOLAC_STATE_DEACTIVATING = 3,
    YOLAC_STATE_ERROR = 4,
} YolacState;

typedef struct YolacFfiConfig {
    uint8_t profile;
    uint16_t mtu;
    uint8_t block_unprotected_ipv6;
} YolacFfiConfig;

typedef struct YolacHandle YolacHandle;

typedef int32_t (*YolacProtectFdFn)(void *ctx, int32_t fd);
typedef void (*YolacPacketSinkFn)(void *ctx, const uint8_t *data, size_t len);
typedef void (*YolacStateChangedFn)(void *ctx, uint8_t state);

YolacHandle *yolac_create(const YolacFfiConfig *cfg);
void yolac_destroy(YolacHandle *handle);

uint8_t yolac_get_state(const YolacHandle *handle);
int32_t yolac_notify_network_change(YolacHandle *handle);

/* Packet-flow mode (iOS NEPacketTunnelProvider): push L3 packets in & receive L3 packets via sink_cb */
int32_t yolac_start_packet_flow(
    YolacHandle *handle,
    YolacPacketSinkFn sink_cb,
    void *sink_ctx,
    YolacStateChangedFn state_cb,
    void *state_ctx
);
int32_t yolac_push_tun_packet(YolacHandle *handle, const uint8_t *data, size_t len);

/* File-descriptor TUN mode (Android VpnService / Unix TUN) */
int32_t yolac_start_tun_fd(
    YolacHandle *handle,
    int32_t tun_fd,
    YolacProtectFdFn protect_cb,
    void *protect_ctx,
    YolacStateChangedFn state_cb,
    void *state_ctx
);

int32_t yolac_stop(YolacHandle *handle);

/* Real module health JSON (7 modules: status 0=gray/passive, 1=green/healthy, 2=red/error).
 * Writes NUL-terminated UTF-8 JSON into out_buf. Returns bytes written (excluding NUL) or negative on error. */
int32_t yolac_get_health_json(YolacHandle *handle, char *out_buf, size_t out_len);

/* User-initiated GitHub Releases update check (never called automatically).
 * Writes NUL-terminated UTF-8 JSON {status, message, release_url} into out_buf. */
int32_t yolac_check_updates_json(YolacHandle *handle, char *out_buf, size_t out_len);

/* Reports a real platform-level error (e.g. OS VPN permission denied = 1) into health state. */
int32_t yolac_report_platform_error(YolacHandle *handle, uint8_t error_code);

/* TULPAR Forge dynamic strategy package loading (zero recompile, SHA-256 + verifier checked) */
int32_t yolac_load_forge_package(YolacHandle *handle, const uint8_t *data, size_t len);
int32_t yolac_unload_forge_package(YolacHandle *handle);
int32_t yolac_get_forge_status_json(YolacHandle *handle, char *out_buf, size_t out_len);

/* TULPAR v0.5 dynamic controls: DNS profile, QUIC mode (0=allow,1=fallback,2=desync), user rules & domain doctor */
int32_t yolac_set_dns_profile_json(YolacHandle *handle, const char *profile_spec);
int32_t yolac_set_quic_policy(YolacHandle *handle, uint8_t mode);
int32_t yolac_set_user_rules_json(YolacHandle *handle, const char *rules_json);
int32_t yolac_diagnose_domain_json(YolacHandle *handle, const char *domain, char *out_buf, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* YOLAC_H */
