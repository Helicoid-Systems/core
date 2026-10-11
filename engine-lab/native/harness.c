/* harness.c — RD02 C harness for the hs_native laboratory ABI.
 *
 * Proves, against the real linked cdylib:
 *   1. explicit ABI/version (static version storage, no leak)
 *   2. constructor + lifetime (null free; free exactly once — no double-free)
 *   3. bounded validated inputs (peer id)
 *   4. Rust panic containment (process survives, status PANIC; NOT UB)
 *   5. real inert Session<NativeHandler> construct via hs_viewer_prepare
 *      - disabled server_keyboard/file/clipboard defaults from real fields
 *      - NativeHandler.get_rgba returns null (no fabricated media)
 *      - process-local LISTEN sockets unchanged (lsof -a; AND-ed, not global)
 *   6. connecting / observation exports return UNAVAILABLE before B03
 *   7. frame ownership: acquire empty is STATE; release null is OK;
 *      channel-binding export stays UNAVAILABLE (no fabricated binding)
 *   8. close drops the real Session; drain is a bounded async transition;
 *      free after drain; request_close during lifecycle does not deadlock
 *   9. context lifetime end-to-end
 *
 * This is NOT media/input/control proof and does not authorize remote control.
 * Prepared means inert, not admitted or ready-to-view. B03 is not passed.
 * Frame lifetime with real pixels is covered by Rust fixture lifetime checks
 * (cfg(test) only); the C harness covers the ABI surface and drain/cancel.
 */
#include "hs_native.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

static int failures = 0;

/* Real lifecycle callback state for the linked harness. */
static int cb_calls;
static int cb_saw_closing;
static hs_engine_ctx *cb_ctx;

/* Real callback: runs on the delivery worker. Re-enters request_close. */
static void real_cb(void *user, uint32_t code, uint32_t generation) {
    (void)user; (void)generation;
    cb_calls++;
    if (code == HS_LIFE_CLOSING) {
        cb_saw_closing++;
        if (cb_ctx) {
            uint32_t st = hs_viewer_request_close(cb_ctx);
            (void)st;
        }
    }
}

static int slow_done;
/* Slow callback: simulates bounded work on the delivery worker. */
static void slow_cb(void *user, uint32_t code, uint32_t generation) {
    (void)user; (void)generation;
    if (code == HS_LIFE_CLOSING) {
        for (volatile int i = 0; i < 200000; i++) { }
        slow_done = 1;
    }
}

/* No-op lifecycle callback used by registration-bound tests. */
static void harness_noop_cb(void *user, uint32_t code, uint32_t generation) {
    (void)user; (void)code; (void)generation;
}

/* Parallel-close worker: one request_close per thread. */
static hs_engine_ctx *pc_ctx;
static volatile int pc_results[8];
static void *pc_close_thread(void *arg) {
    int idx = (int)(intptr_t)arg;
    pc_results[idx] = (int)hs_viewer_request_close(pc_ctx);
    return NULL;
}

static void check(int cond, const char *name) {
    if (cond) {
        printf("ok   %s\n", name);
    } else {
        printf("FAIL %s\n", name);
        failures++;
    }
}

/*
 * Count TCP LISTEN sockets owned by THIS process.
 *
 * `lsof -a` ANDs the -p and -i predicates. Without -a, lsof ORs them and
 * reports system-global listeners (the previous lab's bug).
 * Returns -1 if lsof is unavailable.
 */
static int count_listeners(void) {
    /* Exit 1 is lsof's documented empty selection. Any other exit, malformed
       row, or missing tool is an unavailable check, never fabricated zero. */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/lsof -nP -a -p %d -iTCP -sTCP:LISTEN -F f 2>/dev/null",
             (int)getpid());
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    char buf[256];
    int n = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        if (buf[0] == 'f') n++;
    }
    int read_error = ferror(fp);
    int status = pclose(fp);
    if (read_error || status == -1 || !WIFEXITED(status)) return -1;
    int code = WEXITSTATUS(status);
    if (code == 1 && n == 0) return 0;
    return code == 0 ? n : -1;
}

int main(void) {
    printf("=== hs_native RD02 harness ===\n");

    /* 1. ABI / version (static storage; pointer must be stable) */
    uint32_t abi = hs_abi_version();
    check(abi == 2u, "hs_abi_version == 2 (frame desc gained admission fences)");
    const char *ver = hs_engine_version();
    check(ver != NULL && ver[0] != '\0', "hs_engine_version non-empty");
    const char *ver2 = hs_engine_version();
    check(ver == ver2, "hs_engine_version pointer is stable (no leak)");
    printf("     version = %s\n", ver ? ver : "(null)");

    /* 2. constructor / lifetime */
    hs_engine_ctx *ctx = NULL;
    uint32_t st = hs_engine_ctx_new(&ctx);
    check(st == HS_STATUS_OK && ctx != NULL, "hs_engine_ctx_new");
    check(hs_engine_ctx_new(NULL) == HS_STATUS_NULL, "ctx_new rejects null out");
    check(hs_engine_ctx_free(NULL) == HS_STATUS_OK, "ctx_free accepts null");

    uint32_t state = 0xFFFFFFFFu;
    check(hs_viewer_state(ctx, &state) == HS_STATUS_OK, "hs_viewer_state");
    check(state == HS_STATE_CREATED, "initial state is CREATED (no Session yet)");

    /* 3. bounded validated inputs */
    check(hs_validate_peer_id(NULL, 1) == HS_STATUS_NULL, "validate null id");
    check(hs_validate_peer_id("", 0) == HS_STATUS_INVALID, "validate empty id");
    check(hs_validate_peer_id("ok", 2) == HS_STATUS_OK, "validate ok id");
    check(hs_validate_peer_id("xxxx", HS_MAX_PEER_ID_BYTES + 1) == HS_STATUS_INVALID,
          "validate oversized len");
    char ctrl[3] = {'a', 0, 'b'};
    check(hs_validate_peer_id(ctrl, 3) == HS_STATUS_INVALID, "validate control char");

    /* 4. Rust panic containment (NOT a UB catcher) */
    uint32_t panic_st = hs_debug_inject_panic(ctx);
    check(panic_st == HS_STATUS_PANIC, "Rust panic contained as HS_STATUS_PANIC");
    uint32_t npanics = 0;
    check(hs_panics_contained(ctx, &npanics) == HS_STATUS_OK, "hs_panics_contained");
    check(npanics == 1, "exactly one panic contained");
    check(hs_viewer_state(ctx, &state) == HS_STATUS_OK && state == HS_STATE_CREATED,
          "context usable after contained panic");

    /* 5. real inert Session construct — must NOT start hosting */
    int listeners_before = count_listeners();
    printf("     process-local LISTEN sockets before prepare = %d\n", listeners_before);

    check(hs_viewer_prepare(ctx) == HS_STATUS_OK, "hs_viewer_prepare constructs Session");
    check(hs_viewer_state(ctx, &state) == HS_STATUS_OK && state == HS_STATE_PREPARED,
          "state is PREPARED (inert; not admitted / ready-to-view)");
    check(hs_viewer_prepare(ctx) == HS_STATUS_STATE, "second prepare refused");

    int listeners_after = count_listeners();
    printf("     process-local LISTEN sockets after prepare  = %d\n", listeners_after);
    if (listeners_before >= 0 && listeners_after >= 0) {
        check(listeners_after <= listeners_before,
              "prepare did not add process-local TCP listeners");
    } else {
        check(0, "listener evidence unavailable (lsof failed)");
    }

    /* Disabled server_* permission defaults from the real Session fields. */
    uint32_t flag = 0xFFFFFFFFu;
    check(hs_server_keyboard_enabled(ctx, &flag) == HS_STATUS_OK,
          "hs_server_keyboard_enabled readable");
    check(flag == 0u, "server_keyboard_enabled is disabled by default");
    check(hs_server_file_transfer_enabled(ctx, &flag) == HS_STATUS_OK,
          "hs_server_file_transfer_enabled readable");
    check(flag == 0u, "server_file_transfer_enabled is disabled by default");
    check(hs_server_clipboard_enabled(ctx, &flag) == HS_STATUS_OK,
          "hs_server_clipboard_enabled readable");
    check(flag == 0u, "server_clipboard_enabled is disabled by default");

    /* NativeHandler.get_rgba must be null — no fabricated media buffer. */
    const uint8_t *rgba = (const uint8_t *)0x1;
    check(hs_handler_rgba_ptr(ctx, 0, &rgba) == HS_STATUS_OK, "hs_handler_rgba_ptr ok");
    check(rgba == NULL, "NativeHandler.get_rgba returns null (no fake media)");

    /* 6. connecting / observation are unavailable before B03 */
    check(hs_viewer_connect(ctx, "peer-01", 7) == HS_STATUS_UNAVAILABLE,
          "hs_viewer_connect returns UNAVAILABLE (no network start)");
    uint32_t stream = 0xFFFFFFFFu;
    check(hs_viewer_begin_observation(ctx, 0, &stream) == HS_STATUS_UNAVAILABLE,
          "hs_viewer_begin_observation returns UNAVAILABLE (no stream)");

    /* 7. frame ownership ABI: no fabricated pixels; binding stays unavailable */
    hs_frame *frame = NULL;
    hs_frame_desc desc;
    memset(&desc, 0, sizeof(desc));
    /* Exact native descriptor layout: wrappers must agree on sizeof/offsets.
       Constructing a managed/side descriptor does NOT prove native marshalling —
       these are the linked C ABI's own values. */
    check(sizeof(hs_frame_desc) == 48, "sizeof(hs_frame_desc) == 48 (linked C ABI)");
    check(offsetof(hs_frame_desc, width) == 0, "offsetof(width) == 0");
    check(offsetof(hs_frame_desc, viewer_generation) == 24,
          "offsetof(viewer_generation) == 24");
    check(offsetof(hs_frame_desc, layout_generation) == 28,
          "offsetof(layout_generation) == 28");
    check(offsetof(hs_frame_desc, interaction_generation) == 32,
          "offsetof(interaction_generation) == 32");
    check(offsetof(hs_frame_desc, sequence) == 40, "offsetof(sequence) == 40");
    check(hs_frame_acquire_latest(ctx, 0, &frame, &desc) == HS_STATUS_STATE,
          "hs_frame_acquire_latest empty slot returns STATE (no fake frame)");
    check(hs_frame_release(NULL) == HS_STATUS_OK, "hs_frame_release accepts null");
    uint8_t binding[32];
    uint32_t blen = 32;
    check(hs_channel_binding_export(ctx, binding, &blen) == HS_STATUS_UNAVAILABLE,
          "hs_channel_binding_export stays UNAVAILABLE (no fixture binding)");

    /* Lifecycle poll on empty queue is STATE (no fabricated event). */
    uint32_t ev = 0, evgen = 0;
    check(hs_viewer_poll_life(ctx, &ev, &evgen) == HS_STATUS_STATE,
          "hs_viewer_poll_life empty queue returns STATE");

    /* 8. close drops the real Session; drain is a bounded async transition */
    uint32_t gen_before = 0;
    check(hs_generation(ctx, &gen_before) == HS_STATUS_OK, "hs_generation before close");
    check(hs_viewer_request_close(ctx) == HS_STATUS_OK,
          "hs_viewer_request_close drops Session");
    check(hs_viewer_state(ctx, &state) == HS_STATUS_OK && state == HS_STATE_CLOSING,
          "state is CLOSING after request-close");
    uint32_t gen_after = 0;
    check(hs_generation(ctx, &gen_after) == HS_STATUS_OK, "hs_generation after close");
    check(gen_after > gen_before, "generation fence bumped on close");

    /* Permission reads require Prepared; after close they are refused. */
    check(hs_server_keyboard_enabled(ctx, &flag) == HS_STATUS_STATE,
          "permission read refused after session drop");

    check(hs_viewer_prepare(ctx) == HS_STATUS_EXHAUSTED,
          "prepare after close refused (exhausted)");
    check(hs_viewer_request_close(ctx) == HS_STATUS_OK,
          "request_close idempotent in CLOSING");

    /* request_close during/after lifecycle is non-blocking (no deadlock). */
    check(hs_viewer_request_close(ctx) == HS_STATUS_OK,
          "repeat request_close does not deadlock");

    check(hs_viewer_drain(ctx, 200) == HS_STATUS_OK,
          "hs_viewer_drain completes bounded async drain");
    check(hs_viewer_state(ctx, &state) == HS_STATUS_OK && state == HS_STATE_CLOSED,
          "state is CLOSED after drain");
    check(hs_viewer_drain(ctx, 0) == HS_STATUS_OK, "drain idempotent when CLOSED");
    check(hs_viewer_request_close(ctx) == HS_STATUS_STATE,
          "request_close after CLOSED refused");

    /* 9. lifetime end — free exactly once (no double-free attempt) */
    check(hs_engine_ctx_free(ctx) == HS_STATUS_OK, "hs_engine_ctx_free");

    /* Free-after-close-before-drain path: free with outstanding drain work is
       refused. A second context exercises request_close + immediate free. */
    hs_engine_ctx *ctx2 = NULL;
    check(hs_engine_ctx_new(&ctx2) == HS_STATUS_OK, "second ctx_new");
    check(hs_viewer_prepare(ctx2) == HS_STATUS_OK, "second prepare");
    check(hs_viewer_request_close(ctx2) == HS_STATUS_OK, "second request_close");
    check(hs_viewer_drain(ctx2, 500) == HS_STATUS_OK, "second drain");
    check(hs_engine_ctx_free(ctx2) == HS_STATUS_OK, "second ctx_free after drain");

    /* 10. REAL lifecycle callback execution (not polling). */
    {
        cb_calls = 0;
        cb_saw_closing = 0;
        cb_ctx = NULL;

        hs_engine_ctx *c3 = NULL;
        check(hs_engine_ctx_new(&c3) == HS_STATUS_OK, "callback ctx_new");
        check(hs_viewer_prepare(c3) == HS_STATUS_OK, "callback prepare");
        cb_ctx = c3;
        check(hs_viewer_set_lifecycle_cb(c3, real_cb, NULL) == HS_STATUS_OK,
              "register real lifecycle callback");
        /* Close triggers a real CLOSING event delivered to the worker. */
        check(hs_viewer_request_close(c3) == HS_STATUS_OK, "close for callback");
        check(hs_viewer_drain(c3, 1000) == HS_STATUS_OK, "drain after real callback");
        check(cb_calls >= 1, "real callback executed on delivery worker");
        check(cb_saw_closing == 1, "CLOSING event delivered to real callback");
        check(hs_engine_ctx_free(c3) == HS_STATUS_OK, "free after real callback");
    }

    /* 11. Slow callback: free refused before drain; later drain succeeds. */
    {
        slow_done = 0;
        hs_engine_ctx *c4 = NULL;
        check(hs_engine_ctx_new(&c4) == HS_STATUS_OK, "slow ctx_new");
        check(hs_viewer_prepare(c4) == HS_STATUS_OK, "slow prepare");
        check(hs_viewer_set_lifecycle_cb(c4, slow_cb, NULL) == HS_STATUS_OK,
              "register slow callback");
        check(hs_viewer_request_close(c4) == HS_STATUS_OK, "close for slow callback");
        /* Free before drain is refused (outstanding worker). */
        check(hs_engine_ctx_free(c4) == HS_STATUS_STATE,
              "free refused before drain (worker outstanding)");
        uint32_t drain_st = hs_viewer_drain(c4, 1000);
        check(drain_st == HS_STATUS_OK, "later drain completes after slow callback");
        check(slow_done == 1, "slow callback ran to completion");
        check(hs_engine_ctx_free(c4) == HS_STATUS_OK, "free after slow callback drain");
    }

    /* 12. Polling mode: no callback registered — events retained for poll
          (the worker must not silently discard them). */
    {
        hs_engine_ctx *c5 = NULL;
        check(hs_engine_ctx_new(&c5) == HS_STATUS_OK, "poll ctx_new");
        check(hs_viewer_prepare(c5) == HS_STATUS_OK, "poll prepare");
        check(hs_debug_queue_life(c5, HS_LIFE_FRAME_READY, 1) == HS_STATUS_OK,
              "queue poll event 1");
        check(hs_debug_queue_life(c5, HS_LIFE_FRAME_READY, 2) == HS_STATUS_OK,
              "queue poll event 2");
        usleep(50000); /* worker scheduling window */
        uint32_t code = 0, gen = 0;
        check(hs_viewer_poll_life(c5, &code, &gen) == HS_STATUS_OK,
              "poll retains event 1 under worker scheduling");
        check(code == HS_LIFE_FRAME_READY && gen == 1, "poll event 1 payload");
        check(hs_viewer_poll_life(c5, &code, &gen) == HS_STATUS_OK,
              "poll retains event 2 under worker scheduling");
        check(gen == 2, "poll event 2 payload");
        check(hs_viewer_poll_life(c5, &code, &gen) == HS_STATUS_STATE,
              "poll empty after consuming retained events");
        /* Leftover poll event must not hang close/drain. */
        check(hs_debug_queue_life(c5, HS_LIFE_FRAME_READY, 9) == HS_STATUS_OK,
              "queue leftover poll event");
        check(hs_viewer_request_close(c5) == HS_STATUS_OK, "poll-mode close");
        check(hs_viewer_drain(c5, 1000) == HS_STATUS_OK,
              "poll-mode drain does not hang on retained events");
        check(hs_engine_ctx_free(c5) == HS_STATUS_OK, "poll-mode free");
    }

    /* 13. Registration after close/drain is refused (no publish vs drain race). */
    {
        hs_engine_ctx *c6 = NULL;
        check(hs_engine_ctx_new(&c6) == HS_STATUS_OK, "reg-race ctx_new");
        check(hs_viewer_prepare(c6) == HS_STATUS_OK, "reg-race prepare");
        check(hs_viewer_request_close(c6) == HS_STATUS_OK, "reg-race close");
        check(hs_viewer_set_lifecycle_cb(c6, harness_noop_cb, NULL) == HS_STATUS_STATE,
              "registration refused in CLOSING");
        check(hs_viewer_drain(c6, 500) == HS_STATUS_OK, "reg-race drain");
        check(hs_viewer_set_lifecycle_cb(c6, harness_noop_cb, NULL) == HS_STATUS_STATE,
              "registration refused after drain (no publish vs drain race)");
        check(hs_engine_ctx_free(c6) == HS_STATUS_OK, "reg-race free");
    }

    /* 14. Parallel close: exactly one generation bump, one CLOSING delivery. */
    {
        pc_ctx = NULL;
        check(hs_engine_ctx_new(&pc_ctx) == HS_STATUS_OK, "parallel-close ctx_new");
        check(hs_viewer_prepare(pc_ctx) == HS_STATUS_OK, "parallel-close prepare");
        cb_calls = 0;
        cb_saw_closing = 0;
        cb_ctx = NULL;
        check(hs_viewer_set_lifecycle_cb(pc_ctx, real_cb, NULL) == HS_STATUS_OK,
              "parallel-close register");
        uint32_t gen0 = 0;
        check(hs_generation(pc_ctx, &gen0) == HS_STATUS_OK, "parallel-close gen before");

        pthread_t th[8];
        for (int i = 0; i < 8; i++) {
            pthread_create(&th[i], NULL, pc_close_thread, (void *)(intptr_t)i);
        }
        for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
        int all_ok = 1;
        for (int i = 0; i < 8; i++) {
            if (pc_results[i] != (int)HS_STATUS_OK) all_ok = 0;
        }
        check(all_ok, "every parallel close returns OK");
        uint32_t gen1 = 0;
        check(hs_generation(pc_ctx, &gen1) == HS_STATUS_OK, "parallel-close gen after");
        check(gen1 == gen0 + 1, "exactly one generation bump across parallel close");
        check(hs_viewer_drain(pc_ctx, 1000) == HS_STATUS_OK, "parallel-close drain");
        check(cb_saw_closing == 1, "exactly one CLOSING delivered across parallel close");
        check(hs_engine_ctx_free(pc_ctx) == HS_STATUS_OK, "parallel-close free");
    }

    /* 15. Bounded registrations: native HS_MAX_LIFE_RETIRED limit is enforced. */
    {
        hs_engine_ctx *c7 = NULL;
        check(hs_engine_ctx_new(&c7) == HS_STATUS_OK, "bound ctx_new");
        check(hs_viewer_prepare(c7) == HS_STATUS_OK, "bound prepare");
        check(hs_viewer_set_lifecycle_cb(c7, harness_noop_cb, NULL) == HS_STATUS_OK,
              "bound first registration");
        for (int i = 0; i < (int)HS_MAX_LIFE_RETIRED; i++) {
            check(hs_viewer_set_lifecycle_cb(c7, harness_noop_cb, NULL) == HS_STATUS_OK,
                  "bound replacement allowed");
        }
        check(hs_viewer_set_lifecycle_cb(c7, harness_noop_cb, NULL) == HS_STATUS_EXHAUSTED,
              "bound: registration past HS_MAX_LIFE_RETIRED refused");
        check(hs_viewer_request_close(c7) == HS_STATUS_OK, "bound close");
        check(hs_viewer_drain(c7, 1000) == HS_STATUS_OK, "bound drain");
        check(hs_engine_ctx_free(c7) == HS_STATUS_OK, "bound free");
    }

    printf("=== %s (%d failures) ===\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
