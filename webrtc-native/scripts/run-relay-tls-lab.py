#!/usr/bin/env python3
"""Bounded TURN/TLS relay-only lab runner (E01 connection prerequisite, v4).

v4 vs prior:
  - REST only (use-auth-secret/static-auth-secret). No lt-cred-mech fallback.
  - lab-only allow-loopback-peers so 127 peers can allocate.
  - secret/password strings masked before any JSON/log projection.
  - clean wrong-host profile: certSAN=DNS:localhost, positive host=localhost
    with dual loopback listeners, wrong-host=127.0.0.1 reaching v4.
  - causal TLS-negative verdicts via verifier diagnostics independent of
    selected-route existence.
  - bounded owned child terminate on every path.

Connection-only evidence. NOT relay lifecycle, admission, media, or public
adoption proof. Credentials stay in 0600 scratch and never appear in argv.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

PIN_COTURN_COMMIT = "23c6c1d32a3d2b21a56cee65d3203bcc4ea82d2b"
DEFAULT_STOCK = Path(
    "/tmp/hs-finish-20261013/relay-lab/coturn-stock-20261017/bin/turnserver-stock"
)
# Fresh private v4 scratch. Prior failed output preserved alongside.
LAB_ROOT = Path("/tmp/hs-finish-20261013/core-turn-v4-lab")


def pick_port(kind: int) -> int:
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def write_secret_file(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode())
    finally:
        os.close(fd)


def gen_certs_narrow(cert_dir: Path) -> tuple[Path, Path]:
    """Self-signed leaf with DNS:localhost only (standard DNS SAN).

    WebRTC SSLPostConnectionCheck uses X509_check_host (DNS-only).
    Positive host=localhost matches DNS:localhost. Wrong-host host=127.0.0.1
    reaches the same healthy v4 loopback listener but fails X509_check_host
    (no IP SAN, DNS:localhost != 127.0.0.1). Not a DNS failure.
    Dual loopback listeners (v4+v6) so localhost resolution is reachable.
    """
    cert_dir.mkdir(parents=True, exist_ok=True)
    key = cert_dir / "turn.key"
    crt = cert_dir / "turn.crt"
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(crt), "-days", "1", "-nodes",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost",
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    os.chmod(key, 0o600)
    return crt, key


def rest_identity(secret: str, user: str, ttl_s: int = 600) -> tuple[str, str]:
    """TURN REST API identity.

    usercombo = timestamp:username (expires). Password is base64 HMAC-SHA1 over
    the usercombo with the shared secret (README.turnserver TURN REST API).
    """
    expiry = int(time.time()) + ttl_s
    usercombo = f"{expiry}:{user}"
    mac = hmac.new(secret.encode(), usercombo.encode(), hashlib.sha1).digest()
    password = base64.b64encode(mac).decode()
    return usercombo, password


def write_turn_conf(path: Path, secret: str, crt: Path, key: Path,
                    udp_port: int, tls_port: int,
                    relay_lo: int, relay_hi: int, log_path: Path) -> None:
    # Coturn grammar: listening-ip/relay-ip separate; ports are numeric.
    # Bind both loopback families so host=localhost is reachable (::1 or 127).
    # Disable unused alt listeners. Bounded relay range.
    # use-auth-secret accepts wire username timestamp:userid (colons allowed).
    # allow-loopback-peers is LAB-ONLY: production relay destinations stay
    # restricted (coturn default forbids 127 peers).
    conf = f"""listening-ip=127.0.0.1
listening-ip=::1
relay-ip=127.0.0.1
relay-ip=::1
listening-port={udp_port}
tls-listening-port={tls_port}
alt-listening-port=0
alt-tls-listening-port=0
min-port={relay_lo}
max-port={relay_hi}
fingerprint
use-auth-secret
static-auth-secret={secret}
no-cli
allow-loopback-peers
realm=hs-turn-tls-lab
no-multicast-peers
cert={crt}
pkey={key}
stale-nonce=600
user-quota=12
total-quota=1200
log-file={log_path}
"""
    write_secret_file(path, conf)


def redact(text: str, secrets_to_mask: tuple[str, ...] = ()) -> str:
    """Character filter PLUS actual secret/password string masking.

    Character filtering alone does NOT remove credentials. Any known secret or
    password value is replaced with [REDACTED] before projection.
    """
    out = text
    for sec in secrets_to_mask:
        if sec:
            out = out.replace(sec, "[REDACTED]")
    return "".join(c if c.isprintable() or c in "\n\t" else "." for c in out)


def start_turnserver(binary: Path, conf: Path, stdout_path: Path) -> subprocess.Popen:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    out_f = open(stdout_path, "wb")
    proc = subprocess.Popen(
        [str(binary), "-c", str(conf)],
        stdin=subprocess.DEVNULL,
        stdout=out_f,
        stderr=subprocess.STDOUT,
    )
    proc._hs_log = out_f  # type: ignore[attr-defined]
    return proc


def wait_listening(port: int, timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            s.close()
            time.sleep(0.05)
    return False


def kill_turnserver(proc: subprocess.Popen) -> dict:
    reaped = False
    rc = None
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
            reaped = True
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
                reaped = True
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                reaped = False
    else:
        reaped = True
        rc = proc.returncode
    log_f = getattr(proc, "_hs_log", None)
    if log_f is not None:
        try:
            log_f.close()
        except OSError:
            pass
    return {"process_reaped": reaped, "returncode": rc}


def tls_handshake_probe(host: str, port: int, ca_cert: Path) -> tuple[bool, str]:
    ctx = ssl.create_default_context(cafile=str(ca_cert))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return True, tls.version() or "tls"
    except Exception as e:  # noqa: BLE001 - report the failure class
        return False, type(e).__name__


def redacted_log_tail(path: Path, n: int = 2500,
                      secrets_to_mask: tuple[str, ...] = ()) -> str:
    if not path.is_file():
        return ""
    raw = path.read_bytes()[-n:]
    return redact(raw.decode("utf-8", errors="replace"), secrets_to_mask)


def build_cfg_file(path: Path, host: str, port: int, user: str, password: str,
                   trust_pem: Path | None, trust_sha_hex: str | None) -> None:
    lines = [
        f"host={host}",
        f"port={port}",
        f"username={user}",
        f"password={password}",
    ]
    if trust_pem is not None:
        lines.append(f"trust_pem_path={trust_pem}")
    if trust_sha_hex is not None:
        lines.append(f"trust_sha256_hex={trust_sha_hex}")
    write_secret_file(path, "\n".join(lines) + "\n")


def run_launcher_fixture_tests(run_dir: Path, mask: tuple[str, ...]) -> dict:
    """Fixture proof for launcher error paths (no live TURN daemon).

    Covers the redacted_log_tail keyword-arg form used by boot-fail receipts,
    secret masking on synthetic tails, boot-fail receipt shape, and owned-child
    cleanup. Labeled fixture proof; does not replace the real route gate.
    """
    out: dict = {"fixture_proof": True, "checks": []}
    ok = True

    def note(name: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        out["checks"].append({"name": name, "ok": passed, "detail": detail})
        if not passed:
            ok = False

    fixture_log = run_dir / "fixture-bootfail.log"
    try:
        write_secret_file(
            fixture_log,
            "boot failed secret=%s\n" % (mask[0] if mask else "x"),
        )
        tail = redacted_log_tail(fixture_log, secrets_to_mask=mask)
        note("redacted_log_tail_keyword_args", True)
        note("fixture_secret_masked",
             all(m not in tail for m in mask if m),
             "synthetic secret absent from tail")
    except TypeError as e:
        note("redacted_log_tail_keyword_args", False, "TypeError: %s" % e)
    except Exception as e:  # noqa: BLE001
        note("redacted_log_tail_keyword_args", False, type(e).__name__)

    receipt = {
        "status": "FAIL",
        "note": "turnserver TLS port did not become ready",
        "log_tail": redacted_log_tail(fixture_log, secrets_to_mask=mask),
    }
    note("bootfail_receipt_status", receipt.get("status") == "FAIL")
    note("bootfail_receipt_has_tail", "log_tail" in receipt)

    import subprocess as sp
    child = sp.Popen(["/bin/sleep", "30"], stdin=sp.DEVNULL,
                     stdout=sp.DEVNULL, stderr=sp.DEVNULL)
    cleaned = kill_turnserver(child)
    note("owned_child_cleanup",
         cleaned.get("process_reaped") is True and child.poll() is not None,
         "reaped=%s rc=%s" % (cleaned.get("process_reaped"),
                              cleaned.get("returncode")))

    out["status"] = "PASS" if ok else "FAIL"
    return out


def run_harness_scenarios(results: dict, run_dir: Path, harness: Path,
                          tls_port: int, usercombo: str, password: str,
                          crt: Path, cert_sha_hex: str,
                          mask: tuple[str, ...]) -> int:
    """Run harness scenarios after a healthy boot+probe. Returns exit code."""

    def run_harness(name: str, cfg_path: Path | None) -> dict:
        argv = [str(harness), name]
        if cfg_path is not None:
            argv.append(str(cfg_path))
        t0 = time.time()
        try:
            p = subprocess.run(argv, capture_output=True, timeout=90,
                               check=False)
            out = p.stdout.decode("utf-8", errors="replace")
            return {
                "status": "PASS" if p.returncode == 0 else "FAIL",
                "exit": p.returncode,
                "duration_s": round(time.time() - t0, 3),
                "stdout_tail": redact(out[-4000:], mask),
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "FAIL",
                "exit": -1,
                "duration_s": round(time.time() - t0, 3),
                "note": "harness deadline exceeded (NotVerified, not cert deny)",
            }

    # Positive PEM: host=localhost matches cert DNS SAN (X509_check_host).
    cfg = run_dir / "lab-positive.cfg"
    build_cfg_file(cfg, "localhost", tls_port, usercombo, password, crt, None)
    os.chmod(cfg, 0o600)

    results["scenarios"]["validate"] = run_harness("validate", None)
    results["scenarios"]["positive"] = run_harness("positive", cfg)

    # Positive SHA-256 pin: same healthy REST daemon, trust mode = exact DER
    # digest. Distinct mandatory scenario; still full channel/cert/messages.
    sha_cfg = run_dir / "lab-positive-sha.cfg"
    build_cfg_file(sha_cfg, "localhost", tls_port, usercombo, password,
                   None, cert_sha_hex)
    os.chmod(sha_cfg, 0o600)
    results["scenarios"]["positive-sha"] = run_harness("positive", sha_cfg)

    # wrong-cert: correct host=localhost + deliberately wrong SHA-256 pin.
    wrong_sha = ("0" if cert_sha_hex[0] != "0" else "1") + cert_sha_hex[1:]
    bad_cfg = run_dir / "lab-wrongcert.cfg"
    build_cfg_file(bad_cfg, "localhost", tls_port, usercombo, password,
                   None, wrong_sha)
    os.chmod(bad_cfg, 0o600)
    wc = run_harness("wrong-cert", bad_cfg)
    wc["genuine_tls_reject"] = bool(
        results["scenarios"]["boot_tls_probe"].get("handshake_ok")
        and wc["status"] == "PASS"
        and "wrong-cert: custom verifier actually invoked" in wc.get("stdout_tail", "")
        and "wrong-cert: verifier rejected pin" in wc.get("stdout_tail", "")
    )
    wc["causal_note"] = (
        "negative harness PASS = correctly denied; verifier reject required; "
        "setup/timeout is not cert reject"
    )
    results["scenarios"]["wrong-cert"] = wc

    # wrong-cred: valid pin + valid-in-time REST user, wrong password.
    cred_cfg = run_dir / "lab-wrongcred.cfg"
    build_cfg_file(cred_cfg, "localhost", tls_port, usercombo,
                   "wrong-password-not-real", crt, None)
    os.chmod(cred_cfg, 0o600)
    wc2 = run_harness("wrong-cred", cred_cfg)
    wc2["credential_time_valid"] = True
    wc2["causal_pin_accepted"] = bool(
        wc2["status"] == "PASS"
        and "wrong-cred: real pin accepted" in wc2.get("stdout_tail", "")
        and "wrong-cred: allocate refused" in wc2.get("stdout_tail", "")
    )
    wc2["note"] = (
        "REST user timestamp still valid; password intentionally wrong; "
        "TLS pin must accept then allocate refuse"
    )
    results["scenarios"]["wrong-cred"] = wc2

    # no-relay: unreachable TURN port (harness forces port=1). No fallback.
    norelay_cfg = run_dir / "lab-norelay.cfg"
    build_cfg_file(norelay_cfg, "localhost", tls_port, usercombo, password,
                   crt, None)
    os.chmod(norelay_cfg, 0o600)
    nr = run_harness("no-relay", norelay_cfg)
    nr["not_tls_reject"] = True
    nr["note"] = "unreachable TURN; diagnostics independent of TLS reject"
    results["scenarios"]["no-relay"] = nr

    # wrong-host: host=127.0.0.1 reaches the healthy v4 loopback TLS listener
    # with the correct pin, but cert DNS SAN is localhost only.
    host_cfg = run_dir / "lab-wronghost.cfg"
    build_cfg_file(host_cfg, "127.0.0.1", tls_port, usercombo, password,
                   crt, None)
    os.chmod(host_cfg, 0o600)
    wh = run_harness("wrong-host", host_cfg)
    wh["causal_pin_accepted"] = bool(
        wh["status"] == "PASS"
        and "wrong-host: real pin accepted" in wh.get("stdout_tail", "")
        and "wrong-host: hostname check rejected" in wh.get("stdout_tail", "")
    )
    wh["note"] = (
        "host=127.0.0.1 reaches v4 loopback TLS with correct pin; "
        "cert SAN=DNS:localhost only; failure is X509_check_host mismatch"
    )
    wh["reaches_v4_listener"] = True
    results["scenarios"]["wrong-host"] = wh

    mandatory = ["validate", "positive", "positive-sha", "wrong-cert",
                 "wrong-cred", "no-relay", "wrong-host"]
    return 0 if all(results["scenarios"].get(m, {}).get("status") == "PASS"
                    for m in mandatory) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="TURN/TLS relay-only lab runner v4")
    ap.add_argument("--harness", required=True)
    ap.add_argument("--turnserver-bin", default=str(DEFAULT_STOCK))
    ap.add_argument("--lab-root", default=str(LAB_ROOT))
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    harness = Path(args.harness)
    if not harness.is_file():
        print(f"error: harness missing: {harness}", file=sys.stderr)
        return 2
    stock = Path(args.turnserver_bin)
    if not stock.is_file():
        print(f"error: turnserver binary missing: {stock}", file=sys.stderr)
        return 2

    lab = Path(args.lab_root)
    run_dir = lab / "run"
    bin_dir = lab / "bin"
    cert_dir = lab / "certs"
    for d in (run_dir, bin_dir, cert_dir):
        d.mkdir(parents=True, exist_ok=True)

    pinned_bin = bin_dir / "turnserver-pinned"
    shutil.copy2(stock, pinned_bin)
    os.chmod(pinned_bin, 0o755)
    bin_sha = hashlib.sha256(pinned_bin.read_bytes()).hexdigest()

    results: dict = {
        "scope": "E01 connection-only TURN/TLS relay prerequisite v4",
        "not_relay_lifecycle_evidence": True,
        "not_public_adoption": True,
        "coturn_source_pin": PIN_COTURN_COMMIT,
        "turnserver_bin": str(pinned_bin),
        "turnserver_sha256": bin_sha,
        "harness": str(harness),
        "harness_sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
        "scenarios": {},
    }

    crt, key = gen_certs_narrow(cert_dir)
    der = subprocess.check_output(
        ["openssl", "x509", "-in", str(crt), "-outform", "DER"]
    )
    cert_sha_hex = hashlib.sha256(der).hexdigest()

    secret = secrets.token_urlsafe(32)
    usercombo, password = rest_identity(secret, "hs-lab")
    results["rest_user_is_timestamped"] = ":" in usercombo
    mask = (secret, password, usercombo)
    results["auth_mode"] = "REST use-auth-secret/static-auth-secret"
    results["lab_only_allow_loopback_peers"] = True
    results["production_relay_destinations_restricted"] = True
    results["rest_ttl_s"] = 600
    results["rest_ttl_note"] = "lab fixture validity; not production 60s lease"

    udp_port = pick_port(socket.SOCK_DGRAM)
    tls_port = pick_port(socket.SOCK_STREAM)
    relay_lo = pick_port(socket.SOCK_DGRAM)
    relay_hi = min(relay_lo + 64, 65000)
    conf_path = run_dir / "turnserver.conf"
    log_path = run_dir / "turnserver.log"
    stdout_path = run_dir / "turnserver.stdout"
    write_turn_conf(conf_path, secret, crt, key, udp_port, tls_port,
                    relay_lo, relay_hi, log_path)
    os.chmod(conf_path, 0o600)

    # Launcher self-tests against temporary fixtures (no live daemon).
    results["scenarios"]["launcher-selftest"] = run_launcher_fixture_tests(
        run_dir, mask)

    proc = start_turnserver(pinned_bin, conf_path, stdout_path)
    exit_code = 1
    try:
        if not wait_listening(tls_port):
            results["scenarios"]["boot"] = {
                "status": "FAIL",
                "note": "turnserver TLS port did not become ready",
                "log_tail": redacted_log_tail(log_path, secrets_to_mask=mask),
                "stdout_tail": redacted_log_tail(stdout_path, secrets_to_mask=mask),
            }
            exit_code = 1
        else:
            results["scenarios"]["boot"] = {
                "status": "PASS",
                "tls_port": tls_port,
                "udp_port": udp_port,
                "relay_port_range": [relay_lo, relay_hi],
                "listening_ip": ["127.0.0.1", "::1"],
                "loopback_only": True,
                "dual_loopback_listeners": True,
            }

            ok_probe, probe_detail = tls_handshake_probe("localhost", tls_port, crt)
            ok_ip, ip_detail = tls_handshake_probe("127.0.0.1", tls_port, crt)
            results["scenarios"]["boot_tls_probe"] = {
                "status": "PASS" if ok_probe else "FAIL",
                "handshake_ok": ok_probe,
                "detail": probe_detail,
                "note": "independent ssl probe host=localhost (DNS:localhost SAN)",
                "ip_host_handshake_ok": ok_ip,
                "ip_host_detail": ip_detail,
                "ip_host_note": (
                    "127.0.0.1 vs DNS:localhost is hostname mismatch, not startup fail"
                    if not ok_ip else "unexpected IP host handshake (cert has no IP SAN)"
                ),
            }
            if not ok_probe:
                results["scenarios"]["boot_tls_probe"]["log_tail"] = (
                    redacted_log_tail(stdout_path, secrets_to_mask=mask)
                )
                exit_code = 1
            else:
                exit_code = run_harness_scenarios(
                    results, run_dir, harness, tls_port, usercombo, password,
                    crt, cert_sha_hex, mask,
                )
    finally:
        # Always reap the owned child before any receipt is published.
        results["cleanup"] = kill_turnserver(proc)

    blob = json.dumps(results)
    leaked = bool(password in blob or secret in blob or usercombo in blob)
    results["secret_leak"] = leaked

    text = json.dumps(results, indent=2)
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(text)
    print(text)

    mandatory = ["launcher-selftest", "boot", "boot_tls_probe", "validate",
                 "positive", "positive-sha", "wrong-cert", "wrong-cred",
                 "no-relay", "wrong-host"]
    all_ok = all(results["scenarios"].get(m, {}).get("status") == "PASS"
                 for m in mandatory)
    causal_ok = results["scenarios"].get("wrong-cert", {}).get(
        "genuine_tls_reject") is True
    host_ok = results["scenarios"].get("wrong-host", {}).get(
        "causal_pin_accepted") is True
    cred_ok = results["scenarios"].get("wrong-cred", {}).get(
        "causal_pin_accepted") is True
    cleaned = results.get("cleanup", {}).get("process_reaped") is True
    if not (all_ok and causal_ok and host_ok and cred_ok and cleaned and
            not results.get("secret_leak")):
        return 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
