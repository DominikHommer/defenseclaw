/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* End-to-end speculative execution: a speculatively allowed call that the
 * gateway later blocks must revoke its session and notify the callback. */

#include "defenseclaw.h"
#include "platform.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_state_t *dclaw_get_state(void);
extern int dclaw_mqtt_init(void);
extern int dclaw_mqtt_connect(void);
extern int dclaw_verdict_handle_response(const uint8_t *resp_buf, size_t resp_len,
                                         const uint8_t *pending_tool_hash);
extern void dclaw_verdict_compute_expected_hmac(uint16_t request_id, uint8_t action,
                                                uint8_t severity, uint16_t ttl,
                                                uint8_t reason, uint8_t flags,
                                                uint32_t server_ts,
                                                const uint8_t *tool_hash,
                                                const uint8_t *request_nonce,
                                                uint8_t *out_hmac_32bytes);
extern void dclaw_verdict_set_device_key(const uint8_t *key, size_t key_len);
extern void dclaw_sessions_reset_keep_revoked(void);

static int g_cb_calls;
static uint16_t g_cb_session;

static void on_revoked(uint16_t session_id, const char *tool_name) {
    (void)tool_name;
    g_cb_calls++;
    g_cb_session = session_id;
}

static dclaw_tool_request_t make_request(const char *name, uint8_t caps, uint16_t session) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, name, DCLAW_TOOL_NAME_MAX - 1);
    dclaw_sha256((const uint8_t *)name, strlen(name), req.tool_hash);
    req.cap_flags = caps;
    req.session_id = session;
    return req;
}

static void build_response(uint16_t request_id, uint8_t action,
                           const uint8_t *tool_hash, uint8_t *buf) {
    uint8_t severity = 0, reason = DCLAW_REASON_CLOUD_BLOCK, flags = 0;
    uint16_t ttl = 0;
    uint32_t server_ts = 0x000F4240;
    buf[0] = (uint8_t)(request_id >> 8);
    buf[1] = (uint8_t)(request_id);
    buf[2] = action;
    buf[3] = severity;
    buf[4] = 0; buf[5] = 0;
    buf[6] = reason;
    buf[7] = flags;
    buf[8] = (uint8_t)(server_ts >> 24); buf[9] = (uint8_t)(server_ts >> 16);
    buf[10] = (uint8_t)(server_ts >> 8); buf[11] = (uint8_t)server_ts;
    dclaw_state_t *s = dclaw_get_state();
    uint8_t nonce[4] = {0};
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == request_id && !s->pending[i].resolved) {
            memcpy(nonce, s->pending[i].request_nonce, 4);
            break;
        }
    }
    dclaw_verdict_compute_expected_hmac(request_id, action, severity, ttl, reason,
                                        flags, server_ts, tool_hash, nonce, buf + 12);
}

/* Issue a speculative call and return its request_id (0 if not speculative). */
static uint16_t speculate(const char *name, uint16_t session, uint8_t *hash_out) {
    dclaw_tool_request_t req = make_request(name, DCLAW_CAP_SENSOR_READ, session);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    memcpy(hash_out, req.tool_hash, 32);
    if (v.action != DCLAW_ACTION_ALLOW || v.mode != DCLAW_VERDICT_PENDING) return 0;
    return dclaw_get_state()->next_request_id;
}

static void test_block_revokes_session(void) {
    uint8_t hash[32], resp[44];
    uint16_t rid = speculate("read-sensor", 7, hash);
    assert(rid != 0);

    g_cb_calls = 0;
    build_response(rid, DCLAW_ACTION_BLOCK, hash, resp);
    assert(dclaw_verdict_handle_response(resp, sizeof(resp), hash) == 0);
    assert(g_cb_calls == 1);
    assert(g_cb_session == 7);

    dclaw_tool_request_t next = make_request("sensor_read", DCLAW_CAP_SENSOR_READ, 7);
    dclaw_verdict_t v = dclaw_evaluate(&next);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_RETROACTIVE);
    (void)v;
    printf("  PASS: gateway BLOCK of speculative call revokes its session\n");
}

static void test_other_sessions_unaffected(void) {
    uint8_t hash[32];
    assert(speculate("sensor-read", 8, hash) != 0);
    printf("  PASS: revocation is scoped to one session\n");
}

static void test_allow_does_not_revoke(void) {
    uint8_t hash[32], resp[44];
    uint16_t rid = speculate("read_sensor", 9, hash);
    assert(rid != 0);
    g_cb_calls = 0;
    build_response(rid, DCLAW_ACTION_ALLOW, hash, resp);
    assert(dclaw_verdict_handle_response(resp, sizeof(resp), hash) == 0);
    assert(g_cb_calls == 0);
    assert(speculate("sensor", 9, hash) != 0);
    printf("  PASS: gateway ALLOW leaves the session usable\n");
}

static void test_sync_block_does_not_invoke_callback(void) {
    /* ACTUATE is never speculative: the BLOCK is not retroactive. */
    dclaw_tool_request_t req = make_request("gpio_write", DCLAW_CAP_ACTUATE, 10);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    /* Sync path: PENDING with a live broker, CLOUD_TIMEOUT with the stub. */
    assert(v.action == DCLAW_ACTION_BLOCK);
    (void)v;
    uint16_t rid = dclaw_get_state()->next_request_id;
    uint8_t resp[44];
    g_cb_calls = 0;
    build_response(rid, DCLAW_ACTION_BLOCK, req.tool_hash, resp);
    assert(dclaw_verdict_handle_response(resp, sizeof(resp), req.tool_hash) == 0);
    assert(g_cb_calls == 0);
    uint8_t hash[32];
    assert(speculate("get_state", 10, hash) != 0);
    printf("  PASS: sync-path BLOCK does not revoke the session\n");
}

static void test_full_slots_fall_back_to_sync(void) {
    dclaw_state_t *s = dclaw_get_state();
    memset(s->speculative, 0, sizeof(s->speculative));
    static const char *names[] = {
        "battery_status", "get_temperature", "check_status", "scan_surroundings",
        "check_room_state", "sensor_read", "sensor-read", "read_sensor",
    };
    _Static_assert(DCLAW_SPECULATIVE_SLOTS <= sizeof(names) / sizeof(names[0]),
                   "need one trusted tool name per speculative slot");
    uint8_t hash[32];
    for (int i = 0; i < DCLAW_SPECULATIVE_SLOTS; i++) {
        assert(speculate(names[i], (uint16_t)(20 + i), hash) != 0);
    }
    dclaw_tool_request_t req = make_request("list_devices", DCLAW_CAP_SENSOR_READ, 30);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    (void)v;
    printf("  PASS: no free speculative slot -> synchronous wait\n");
}

static void test_session_reset_keeps_revocations(void) {
    /* Session 7 was revoked above; sessions 20.. have unverified
     * speculative calls in flight. */
    dclaw_sessions_reset_keep_revoked();
    dclaw_tool_request_t a = make_request("get_history", DCLAW_CAP_SENSOR_READ, 7);
    dclaw_verdict_t v = dclaw_evaluate(&a);
    assert(v.reason == DCLAW_REASON_RETROACTIVE);
    dclaw_tool_request_t b = make_request("get_sensors", DCLAW_CAP_SENSOR_READ, 20);
    v = dclaw_evaluate(&b);
    assert(v.reason == DCLAW_REASON_RETROACTIVE);
    (void)v;
    printf("  PASS: session reset keeps revoked and in-flight speculative sessions denied\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);
    dclaw_mqtt_init();
    dclaw_mqtt_connect();
    uint8_t key[32];
    memset(key, 0x42, 32);
    dclaw_verdict_set_device_key(key, 32);
    dclaw_register_retroactive_callback(on_revoked);

    printf("test_speculative_revocation:\n");
    test_block_revokes_session();
    test_other_sessions_unaffected();
    test_allow_does_not_revoke();
    test_sync_block_does_not_invoke_callback();
    test_full_slots_fall_back_to_sync();
    test_session_reset_keeps_revocations();
    printf("  ALL PASSED (6 tests)\n");

    dclaw_shutdown();
    return 0;
}
