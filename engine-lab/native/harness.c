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
 *   7. close drops the real Session; drain is a synchronous transition
 *      (NOT an async cancellation proof)
 *   8. context lifetime end-to-end
 *
 * This is NOT media/input/control proof and does not authorize remote control.
 * Prepared means inert, not admitted or ready-to-view. B03 is not passed.
 */
#include "hs_native.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static int failures = 0;

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
    check(abi == 1u, "hs_abi_version == 1");
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

    /* 7. close drops the real Session; drain is synchronous */
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

    check(hs_viewer_drain(ctx, 0) == HS_STATUS_OK,
          "hs_viewer_drain (synchronous transition; not async cancel proof)");
    check(hs_viewer_state(ctx, &state) == HS_STATUS_OK && state == HS_STATE_CLOSED,
          "state is CLOSED after drain");
    check(hs_viewer_drain(ctx, 0) == HS_STATUS_OK, "drain idempotent when CLOSED");
    check(hs_viewer_request_close(ctx) == HS_STATUS_STATE,
          "request_close after CLOSED refused");

    /* 8. lifetime end — free exactly once (no double-free attempt) */
    check(hs_engine_ctx_free(ctx) == HS_STATUS_OK, "hs_engine_ctx_free");

    printf("=== %s (%d failures) ===\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
