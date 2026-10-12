/* windows-harness.c — RD02 Windows C harness for the hs_native laboratory ABI.
 *
 * Portable native counterpart of harness.c. Proves, against the real linked
 * cdylib (librustdesk.dll), on Windows x64 only:
 *   1. explicit ABI/version (static version storage, no leak) + ABI2 descriptor
 *      width/offset contract + all 27 hs_ lab exports resolve
 *   2. constructor + lifetime (null free; free exactly once)
 *   3. bounded validated inputs (peer id)
 *   4. Rust panic containment (process survives, status PANIC; NOT UB)
 *   5. real inert Session<NativeHandler> construct via hs_viewer_prepare
 *      - disabled server_keyboard/file/clipboard defaults from real fields
 *      - NativeHandler.get_rgba returns null (no fabricated media)
 *      - process-owned TCP LISTEN sockets unchanged (GetExtendedTcpTable,
 *        IPv4 + IPv6 with correct table types; query failure is never
 *        reported as a real zero)
 *   6. connecting / observation exports return UNAVAILABLE before B03
 *   7. frame ownership: acquire empty is STATE; release null is OK;
 *      channel-binding export stays UNAVAILABLE
 *   8. close drops the real Session; drain is a bounded async transition;
 *      free refused until actual drain; re-entrant request_close is safe
 *   9. real async lifecycle callback (re-entrant close), slow receiver held
 *      on a Win32 event barrier, poll-mode retention, post-close
 *      registration refusal, bounded registrations, parallel close
 *      (exactly one generation bump)
 *
 * This is NOT media/input/control proof and does not authorize remote
 * control. Prepared means inert, not admitted or ready-to-view. B03 is not
 * passed. Frame-lifetime fixtures stay in Rust cfg(test); this harness uses
 * retained lab hooks only for lifetime fixtures, never normal pixels.
 *
 * Concurrency uses real Win32 threads and events (CreateThread /
 * WaitForMultipleObjects / CreateEvent). Listener counting uses iphlpapi
 * GetExtendedTcpTable with the correct IPv4/IPv6 row types, filtered to
 * this process id. Never starts endpoint hosting.
 */
#include "hs_native.h"

#ifndef _WIN32
#error "windows-harness.c is the Windows native counterpart; build it with MSVC on Windows"
#endif

/* winsock2 must precede windows.h or the Winsock 1.1 headers conflict. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define PC_THREADS 8
#define LISTENER_ALLOC_CAP (1u << 20) /* 1 MiB bound on table allocation */
#define LISTENER_QUERY_RETRIES 4

static int failures = 0;

static void check(int cond, const char *name) {
    if (cond) {
        printf("ok   %s\n", name);
    } else {
        printf("FAIL %s\n", name);
        failures++;
    }
}

/* ---- shared lifecycle callback state (Win32 atomics / events) ---- */

static volatile LONG cb_calls;
static volatile LONG cb_saw_closing;
static hs_engine_ctx *cb_ctx; /* set before threads/cb run; cleared after join */

static void real_cb(void *user, uint32_t code, uint32_t generation) {
    (void)user;
    (void)generation;
    if (code == HS_LIFE_CLOSING) {
        InterlockedIncrement(&cb_saw_closing);
        if (cb_ctx) {
            uint32_t st = hs_viewer_request_close(cb_ctx);
            (void)st;
        }
    }
    InterlockedIncrement(&cb_calls);
}

/* Slow callback holds on an event so the main thread can observe
 * close-during-callback and prove free is refused while the worker is
 * inside the callback. A spin loop is not a reliable barrier. */
static HANDLE slow_entered;
static HANDLE slow_release;
static volatile LONG slow_finished;
static volatile LONG slow_event_api_failures;

static void slow_cb(void *user, uint32_t code, uint32_t generation) {
    (void)user;
    (void)generation;
    if (code == HS_LIFE_CLOSING) {
        if (!SetEvent(slow_entered)) {
            InterlockedIncrement(&slow_event_api_failures);
        }
        DWORD ws = WaitForSingleObject(slow_release, 5000);
        if (ws != WAIT_OBJECT_0) {
            InterlockedIncrement(&slow_event_api_failures);
        }
        InterlockedExchange(&slow_finished, 1);
    }
}

static void harness_noop_cb(void *user, uint32_t code, uint32_t generation) {
    (void)user;
    (void)code;
    (void)generation;
}

/* ---- parallel close workers ---- */

static hs_engine_ctx *pc_ctx;
static volatile LONG pc_results[PC_THREADS];

static DWORD WINAPI pc_close_thread(LPVOID arg) {
    int idx = (int)(intptr_t)arg;
    pc_results[idx] = (LONG)hs_viewer_request_close(pc_ctx);
    return 0;
}

/*
 * Count TCP LISTEN sockets owned by THIS process.
 *
 * Uses GetExtendedTcpTable with the correct table/row type per family
 * (MIB_TCPTABLE_OWNER_PID vs MIB_TCP6TABLE_OWNER_PID). Allocation is
 * bounded and the table query retries on ERROR_INSUFFICIENT_BUFFER.
 * Returns -1 on any query/allocation failure — never a fabricated zero.
 * Returns >= 0 only after both family queries succeed.
 */
static int count_listeners(void) {
    DWORD pid = GetCurrentProcessId();
    int total = 0;

    /* IPv4 */
    {
        PMIB_TCPTABLE_OWNER_PID table = NULL;
        DWORD size = 0;
        DWORD rv = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                                       TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (rv != ERROR_INSUFFICIENT_BUFFER) {
            return -1;
        }
        for (int attempt = 0; attempt < LISTENER_QUERY_RETRIES; attempt++) {
            if (size == 0 || size > LISTENER_ALLOC_CAP) {
                return -1;
            }
            table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
            if (!table) {
                return -1;
            }
            rv = GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                                     TCP_TABLE_OWNER_PID_LISTENER, 0);
            if (rv == NO_ERROR) {
                break;
            }
            free(table);
            table = NULL;
            if (rv != ERROR_INSUFFICIENT_BUFFER) {
                return -1;
            }
            /* size was updated; retry with the larger buffer */
        }
        if (!table) {
            return -1;
        }
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            if (table->table[i].dwOwningPid == pid) {
                total++;
            }
        }
        free(table);
    }

    /* IPv6 — distinct table/row type; must NOT cast to the IPv4 struct. */
    {
        PMIB_TCP6TABLE_OWNER_PID table = NULL;
        DWORD size = 0;
        DWORD rv = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6,
                                       TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (rv != ERROR_INSUFFICIENT_BUFFER) {
            return -1;
        }
        for (int attempt = 0; attempt < LISTENER_QUERY_RETRIES; attempt++) {
            if (size == 0 || size > LISTENER_ALLOC_CAP) {
                return -1;
            }
            table = (PMIB_TCP6TABLE_OWNER_PID)malloc(size);
            if (!table) {
                return -1;
            }
            rv = GetExtendedTcpTable(table, &size, FALSE, AF_INET6,
                                     TCP_TABLE_OWNER_PID_LISTENER, 0);
            if (rv == NO_ERROR) {
                break;
            }
            free(table);
            table = NULL;
            if (rv != ERROR_INSUFFICIENT_BUFFER) {
                return -1;
            }
        }
        if (!table) {
            return -1;
        }
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            if (table->table[i].dwOwningPid == pid) {
                total++;
            }
        }
        free(table);
    }

    return total;
}

static void sleep_ms(DWORD ms) { Sleep(ms); }

int main(void) {
    printf("=== hs_native RD02 Windows harness ===\n");

    /* 1. ABI / version (static storage; pointer must be stable) */
    uint32_t abi = hs_abi_version();
    check(abi == 2u, "hs_abi_version == 2 (frame desc gained admission fences)");
    const char *ver = hs_engine_version();
    check(ver != NULL && ver[0] != '\0', "hs_engine_version non-empty");
    const char *ver2 = hs_engine_version();
    check(ver == ver2, "hs_engine_version pointer is stable (no leak)");
    printf("     version = %s\n", ver ? ver : "(null)");

    /* Descriptor width/offset contract (ABI2). */
    check(sizeof(hs_frame_desc) == 48, "sizeof(hs_frame_desc) == 48 (linked C ABI)");
    check(offsetof(hs_frame_desc, width) == 0, "offsetof(width) == 0");
    check(offsetof(hs_frame_desc, height) == 4, "offsetof(height) == 4");
    check(offsetof(hs_frame_desc, stride) == 8, "offsetof(stride) == 8");
    check(offsetof(hs_frame_desc, format) == 12, "offsetof(format) == 12");
    check(offsetof(hs_frame_desc, length) == 16, "offsetof(length) == 16");
    check(offsetof(hs_frame_desc, display) == 20, "offsetof(display) == 20");
    check(offsetof(hs_frame_desc, viewer_generation) == 24,
          "offsetof(viewer_generation) == 24");
    check(offsetof(hs_frame_desc, layout_generation) == 28,
          "offsetof(layout_generation) == 28");
    check(offsetof(hs_frame_desc, interaction_generation) == 32,
          "offsetof(interaction_generation) == 32");
    check(offsetof(hs_frame_desc, sequence) == 40, "offsetof(sequence) == 40");

    /* 27 lab exports resolve from the linked DLL. */
    {
        HMODULE mod = GetModuleHandleW(L"librustdesk.dll");
        if (!mod) {
            mod = GetModuleHandleW(L"liblibrustdesk.dll");
        }
        check(mod != NULL, "engine DLL module handle available");
        if (mod) {
            static const char *exports[27] = {
                "hs_abi_version",
                "hs_engine_version",
                "hs_engine_ctx_new",
                "hs_engine_ctx_free",
                "hs_validate_peer_id",
                "hs_viewer_prepare",
                "hs_viewer_state",
                "hs_viewer_request_close",
                "hs_viewer_drain",
                "hs_panics_contained",
                "hs_debug_inject_panic",
                "hs_debug_queue_life",
                "hs_generation",
                "hs_server_keyboard_enabled",
                "hs_server_file_transfer_enabled",
                "hs_server_clipboard_enabled",
                "hs_handler_rgba_ptr",
                "hs_viewer_connect",
                "hs_viewer_begin_observation",
                "hs_frame_acquire_latest",
                "hs_frame_pixels",
                "hs_frame_get_desc",
                "hs_frame_release",
                "hs_frame_stats",
                "hs_viewer_set_lifecycle_cb",
                "hs_viewer_poll_life",
                "hs_channel_binding_export",
            };
            int missing = 0;
            for (int i = 0; i < 27; i++) {
                if ((void *)GetProcAddress(mod, exports[i]) == NULL) {
                    printf("     missing export: %s\n", exports[i]);
                    missing++;
                }
            }
            check(missing == 0, "all 27 lab exports resolve from the real DLL");
        }
    }

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
    printf("     process-owned TCP LISTEN sockets before prepare = %d\n",
           listeners_before);
    check(listeners_before >= 0,
          "listener query succeeded before prepare (no hidden query failure)");

    check(hs_viewer_prepare(ctx) == HS_STATUS_OK, "hs_viewer_prepare constructs Session");
    check(hs_viewer_state(ctx, &state) == HS_STATUS_OK && state == HS_STATE_PREPARED,
          "state is PREPARED (inert; not admitted / ready-to-view)");
    check(hs_viewer_prepare(ctx) == HS_STATUS_STATE, "second prepare refused");

    int listeners_after = count_listeners();
    printf("     process-owned TCP LISTEN sockets after prepare  = %d\n",
           listeners_after);
    if (listeners_before >= 0 && listeners_after >= 0) {
        check(listeners_after <= listeners_before,
              "prepare did not add process-owned TCP listeners");
    } else {
        check(0, "listener evidence unavailable (GetExtendedTcpTable failed)");
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
    check(hs_viewer_request_close(ctx) == HS_STATUS_OK,
          "repeat request_close does not deadlock");

    check(hs_viewer_drain(ctx, 200) == HS_STATUS_OK,
          "hs_viewer_drain completes bounded async drain");
    check(hs_viewer_state(ctx, &state) == HS_STATUS_OK && state == HS_STATE_CLOSED,
          "state is CLOSED after drain");
    check(hs_viewer_drain(ctx, 0) == HS_STATUS_OK, "drain idempotent when CLOSED");
    check(hs_viewer_request_close(ctx) == HS_STATUS_STATE,
          "request_close after CLOSED refused");

    /* 9. lifetime end — free exactly once */
    check(hs_engine_ctx_free(ctx) == HS_STATUS_OK, "hs_engine_ctx_free");

    /* Free-after-close-before-drain path. */
    hs_engine_ctx *ctx2 = NULL;
    check(hs_engine_ctx_new(&ctx2) == HS_STATUS_OK, "second ctx_new");
    check(hs_viewer_prepare(ctx2) == HS_STATUS_OK, "second prepare");
    check(hs_viewer_request_close(ctx2) == HS_STATUS_OK, "second request_close");
    check(hs_viewer_drain(ctx2, 500) == HS_STATUS_OK, "second drain");
    check(hs_engine_ctx_free(ctx2) == HS_STATUS_OK, "second ctx_free after drain");

    /* 10. REAL lifecycle callback execution (not polling). */
    {
        InterlockedExchange(&cb_calls, 0);
        InterlockedExchange(&cb_saw_closing, 0);
        cb_ctx = NULL;

        hs_engine_ctx *c3 = NULL;
        check(hs_engine_ctx_new(&c3) == HS_STATUS_OK, "callback ctx_new");
        check(hs_viewer_prepare(c3) == HS_STATUS_OK, "callback prepare");
        cb_ctx = c3;
        check(hs_viewer_set_lifecycle_cb(c3, real_cb, NULL) == HS_STATUS_OK,
              "register real lifecycle callback");
        check(hs_viewer_request_close(c3) == HS_STATUS_OK, "close for callback");
        check(hs_viewer_drain(c3, 1000) == HS_STATUS_OK, "drain after real callback");
        check(InterlockedCompareExchange(&cb_calls, 0, 0) >= 1,
              "real callback executed on delivery worker");
        check(InterlockedCompareExchange(&cb_saw_closing, 0, 0) == 1,
              "CLOSING event delivered to real callback");
        cb_ctx = NULL;
        check(hs_engine_ctx_free(c3) == HS_STATUS_OK, "free after real callback");
    }

    /* 11. Slow callback held on an event barrier:
     *     free is refused while the callback still holds; release, drain
     *     joins the worker, THEN slow_finished is observed (it is set by
     *     the callback after slow_release), then free succeeds.
     *     Uncertain entry never closes events or frees the context. */
    {
        slow_entered = CreateEventW(NULL, TRUE, FALSE, NULL);
        slow_release = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!slow_entered || !slow_release) {
            check(0, "CreateEventW for slow-callback barrier");
            if (slow_entered) {
                if (!CloseHandle(slow_entered)) {
                    check(0, "CloseHandle slow_entered after partial CreateEventW failure");
                }
                slow_entered = NULL;
            }
            if (slow_release) {
                if (!CloseHandle(slow_release)) {
                    check(0, "CloseHandle slow_release after partial CreateEventW failure");
                }
                slow_release = NULL;
            }
        } else {
            InterlockedExchange(&slow_finished, 0);
            InterlockedExchange(&slow_event_api_failures, 0);
            hs_engine_ctx *c4 = NULL;
            check(hs_engine_ctx_new(&c4) == HS_STATUS_OK, "slow ctx_new");
            check(hs_viewer_prepare(c4) == HS_STATUS_OK, "slow prepare");
            check(hs_viewer_set_lifecycle_cb(c4, slow_cb, NULL) == HS_STATUS_OK,
                  "register slow callback");
            check(hs_viewer_request_close(c4) == HS_STATUS_OK, "close for slow callback");

            DWORD entered = WaitForSingleObject(slow_entered, 2000);
            check(entered == WAIT_OBJECT_0, "slow callback entered and holds");
            if (entered != WAIT_OBJECT_0) {
                /* Callback may still be running. Never free the context or
                   close events that the callback might use. Fail the process
                   safely so this uncertainty cannot become a UAF. */
                fprintf(stderr,
                        "slow-callback entry uncertain (wait=%lu); "
                        "aborting without free or event close\n",
                        (unsigned long)entered);
                fflush(stdout);
                fflush(stderr);
                ExitProcess(2);
            }

            check(InterlockedCompareExchange(&slow_finished, 0, 0) == 0,
                  "slow callback remains inside the release barrier");
            uint32_t early_free = hs_engine_ctx_free(c4);
            check(early_free == HS_STATUS_STATE,
                  "free refused while slow callback still holds");
            if (early_free != HS_STATUS_STATE) {
                /* An unexpected successful free makes further pointer use unsafe. */
                ExitProcess(2);
            }

            if (!SetEvent(slow_release)) {
                check(0, "SetEvent(slow_release)");
            }

            uint32_t drain_st = hs_viewer_drain(c4, 1000);
            check(drain_st == HS_STATUS_OK, "later drain completes after slow callback");
            if (drain_st != HS_STATUS_OK) {
                /* The worker may still hold these event handles or context. */
                fprintf(stderr, "slow-callback drain uncertain; aborting without cleanup\n");
                ExitProcess(2);
            }
            /* Only after a successful drain is the worker joined, so the
               callback has finished WaitForSingleObject(slow_release) and
               stored slow_finished. Observing it earlier is a race. */
            if (drain_st == HS_STATUS_OK) {
                check(InterlockedCompareExchange(&slow_finished, 0, 0) == 1,
                      "slow callback completed before drain finished");
            }
            check(InterlockedCompareExchange(&slow_event_api_failures, 0, 0) == 0,
                  "no SetEvent failures on the slow-callback barrier");
            check(hs_engine_ctx_free(c4) == HS_STATUS_OK, "free after slow callback drain");

            /* Callback is done (drain joined the worker); events are safe to close. */
            if (!CloseHandle(slow_entered)) {
                check(0, "CloseHandle slow_entered");
            }
            slow_entered = NULL;
            if (!CloseHandle(slow_release)) {
                check(0, "CloseHandle slow_release");
            }
            slow_release = NULL;
        }
    }

    /* 12. Polling mode: no callback registered — events retained for poll. */
    {
        hs_engine_ctx *c5 = NULL;
        check(hs_engine_ctx_new(&c5) == HS_STATUS_OK, "poll ctx_new");
        check(hs_viewer_prepare(c5) == HS_STATUS_OK, "poll prepare");
        check(hs_debug_queue_life(c5, HS_LIFE_FRAME_READY, 1) == HS_STATUS_OK,
              "queue poll event 1");
        check(hs_debug_queue_life(c5, HS_LIFE_FRAME_READY, 2) == HS_STATUS_OK,
              "queue poll event 2");
        sleep_ms(50); /* worker scheduling window */
        uint32_t code = 0, gen = 0;
        check(hs_viewer_poll_life(c5, &code, &gen) == HS_STATUS_OK,
              "poll retains event 1 under worker scheduling");
        check(code == HS_LIFE_FRAME_READY && gen == 1, "poll event 1 payload");
        check(hs_viewer_poll_life(c5, &code, &gen) == HS_STATUS_OK,
              "poll retains event 2 under worker scheduling");
        check(gen == 2, "poll event 2 payload");
        check(hs_viewer_poll_life(c5, &code, &gen) == HS_STATUS_STATE,
              "poll empty after consuming retained events");
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

    /* 14. Parallel close: exactly one generation bump, one CLOSING delivery.
     *     Handles are zero-initialized, only created threads are joined,
     *     wait success is checked, and the context is never freed while a
     *     thread may still be running. An uncertain wait fails the process
     *     without freeing. */
    {
        pc_ctx = NULL;
        check(hs_engine_ctx_new(&pc_ctx) == HS_STATUS_OK, "parallel-close ctx_new");
        check(hs_viewer_prepare(pc_ctx) == HS_STATUS_OK, "parallel-close prepare");
        InterlockedExchange(&cb_calls, 0);
        InterlockedExchange(&cb_saw_closing, 0);
        cb_ctx = NULL;
        check(hs_viewer_set_lifecycle_cb(pc_ctx, real_cb, NULL) == HS_STATUS_OK,
              "parallel-close register");
        uint32_t gen0 = 0;
        check(hs_generation(pc_ctx, &gen0) == HS_STATUS_OK, "parallel-close gen before");

        HANDLE th[PC_THREADS];
        int created = 0;
        for (int i = 0; i < PC_THREADS; i++) {
            th[i] = NULL;
        }
        for (int i = 0; i < PC_THREADS; i++) {
            th[i] = CreateThread(NULL, 0, pc_close_thread, (LPVOID)(intptr_t)i, 0, NULL);
            if (!th[i]) {
                check(0, "CreateThread for parallel close");
                break;
            }
            created++;
        }

        if (created > 0) {
            DWORD wr = WaitForMultipleObjects((DWORD)created, th, TRUE, 10000);
            if (wr != WAIT_OBJECT_0) {
                fprintf(stderr,
                        "parallel-close wait uncertain (wr=%lu, created=%d); "
                        "aborting process without freeing pc_ctx\n",
                        (unsigned long)wr, created);
                fflush(stdout);
                fflush(stderr);
                for (int i = 0; i < created; i++) {
                    if (th[i]) {
                        CloseHandle(th[i]);
                    }
                }
                ExitProcess(2);
            }
            for (int i = 0; i < created; i++) {
                if (th[i]) {
                    if (!CloseHandle(th[i])) {
                        check(0, "CloseHandle parallel-close thread");
                    }
                    th[i] = NULL;
                }
            }
        }

        int all_ok = 1;
        for (int i = 0; i < created; i++) {
            if (pc_results[i] != (LONG)HS_STATUS_OK) {
                all_ok = 0;
            }
        }
        check(created == PC_THREADS, "all parallel-close threads created");
        check(all_ok, "every parallel close returns OK");
        uint32_t gen1 = 0;
        check(hs_generation(pc_ctx, &gen1) == HS_STATUS_OK, "parallel-close gen after");
        check(gen1 == gen0 + 1, "exactly one generation bump across parallel close");
        check(hs_viewer_drain(pc_ctx, 1000) == HS_STATUS_OK, "parallel-close drain");
        check(InterlockedCompareExchange(&cb_saw_closing, 0, 0) == 1,
              "exactly one CLOSING delivered across parallel close");
        cb_ctx = NULL;
        check(hs_engine_ctx_free(pc_ctx) == HS_STATUS_OK, "parallel-close free");
        pc_ctx = NULL;
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

    /* Remaining limitations (explicit, not claimed):
     *  - malformed frame geometry / latest-queue supersede / outstanding
     *    frame-after-close are Rust cfg(test) fixture lifetime checks; the C
     *    ABI has no fixture-seal hook and must not invent pixels.
     *  - real media frames, input, grants, authority, channel binding, and
     *    route adoption stay UNAVAILABLE / NOT PROVED.
     *  - no endpoint hosting is started at any point. */

    printf("=== %s (%d failures) ===\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
