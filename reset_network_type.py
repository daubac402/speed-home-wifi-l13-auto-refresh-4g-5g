#!/usr/bin/env python3
"""
Reset the mobile connection of a Speed Wi-Fi HOME 5G L13 router by toggling
the Preferred Network Type (Settings -> Network -> Mobile Network):

    currently 5G  ->  set 4G -> Apply -> set 5G -> Apply
    currently 4G  ->  set 5G -> Apply -> set 4G -> Apply

The web page http://192.168.0.1/index.html#mobile_network is a JavaScript UI
on top of a JSON "goform" HTTP API. This script talks to that API directly:

    GET  /goform/goform_get_cmd_process   (read settings)
    POST /goform/goform_set_cmd_process   (login / apply settings)

Protocol details (reverse-engineered from the router's own js/service.js):

  * Login token:  GET cmd=LD  (requires a Referer header)
    password    = SHA256( SHA256(password) + LD )
    POST goformId=LOGIN  -> result "0" or "4" means success.
  * Every other SET request needs an anti-tamper value:
    AD = SHA256( SHA256(wa_inner_version + cr_version) + RD )
  * Preferred Network Type values:
    "LTE_AND_5G" = 5G Preferred, "Only_LTE" = 4G Only
  * Applying: POST goformId=SET_BEARER_PREFERENCE, BearerPreference=<value>,
    sa_nsa_mode_disable_setting=<"disable_mode_sa"|"disable_mode_none">
    (the SA/NSA radio is forced off when 4G Only is selected, like the UI does)

Usage:
    python3 reset_network_type.py            # do the toggle
    python3 reset_network_type.py --dry-run  # login + show plan, change nothing

Password is read from the ROUTER_PASSWORD key in .env (see .env.example).
No third-party packages required.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

# --------------------------------------------------------------------------
# Non-sensitive configuration (constants)
# --------------------------------------------------------------------------
BASE_URL = "http://192.168.0.1"
LOGIN_PAGE_URL = f"{BASE_URL}/index.html#mobile_network"
GET_URL = f"{BASE_URL}/goform/goform_get_cmd_process"
SET_URL = f"{BASE_URL}/goform/goform_set_cmd_process"
HTTP_HEADERS = {"Referer": f"{BASE_URL}/index.html"}
REQUEST_TIMEOUT = 15  # seconds per HTTP request

# Preferred Network Type values (as used by the router UI)
MODE_5G = "LTE_AND_5G"  # "5G Preferred"
MODE_4G = "Only_LTE"    # "4G Only"
MODE_LABELS = {
    MODE_5G: "5G Preferred",
    MODE_4G: "4G Only",
    "Only_5G": "5G SA",
}

# 5G Standalone setting sent together with the network type
SA_MODE_DISABLED = "disable_mode_sa"   # 5G standalone: disabled (forced on 4G)
SA_MODE_ENABLED = "disable_mode_none"  # 5G standalone: enabled
SA_MODE_LABELS = {SA_MODE_DISABLED: "disabled", SA_MODE_ENABLED: "enabled"}

# Timing
SETTLE_SECONDS = 15   # wait after an Apply so the modem can re-register
POLL_INTERVAL = 2.0   # seconds between verification reads
POLL_TIMEOUT = 30.0    # max seconds to wait for net_select to reflect an Apply
APPLY_RETRIES = 5      # attempts for each Apply (router can refuse while the
APPLY_RETRY_WAIT = 10  # modem is re-registering; retry after these many seconds)

# Behaviour
LOGOUT_WHEN_DONE = True
LOG_HTTP = True  # log every request/response (values shown are hashes/tokens, never the plaintext password)

# Sensitive value: read from .env (or environment), never hardcoded here
ENV_FILE = ".env"
ENV_PASSWORD_KEY = "ROUTER_PASSWORD"

# Login response codes (goformId=LOGIN)
LOGIN_RESULT_MESSAGES = {
    "0": "success",
    "4": "success",
    "1": "login failed",
    "2": "another session is logged in (duplicate user) - log out from your browser",
    "3": "wrong password",
    "5": "login not possible (device/SIM state)",
}

OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))


class RouterError(Exception):
    pass


# --------------------------------------------------------------------------
# HTTP / goform helpers
# --------------------------------------------------------------------------
def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def sha256_hex(text: str) -> str:
    # The router's JavaScript SHA256 returns UPPERCASE hex (e.g. "F49FB8...");
    # the server-side comparison is case-sensitive, so match it exactly.
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


def http_request(url: str, params: dict, post: bool = False) -> dict:
    method = "POST" if post else "GET"
    if LOG_HTTP:
        log(f"--> {method} {url.replace(BASE_URL, '')} params={params}")
    if post:
        data = urllib.parse.urlencode(params).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={**HTTP_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        )
    else:
        req = urllib.request.Request(
            f"{url}?{urllib.parse.urlencode(params)}", headers=HTTP_HEADERS
        )
    try:
        with OPENER.open(req, timeout=REQUEST_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        log(f"<-- {method} network error: {exc}")
        raise RouterError(f"Cannot reach router at {BASE_URL}: {exc}") from exc
    if LOG_HTTP:
        log(f"<-- {method} response: {body}")
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise RouterError(f"Unexpected non-JSON response from router: {body!r}") from exc


def get_cmd(cmds) -> dict:
    """GET one or more settings: get_cmd('net_select') or get_cmd(['a','b'])."""
    if isinstance(cmds, str):
        cmds = [cmds]
    return http_request(
        GET_URL,
        {"cmd": ",".join(cmds), "multi_data": "1", "_": int(time.time() * 1000)},
    )


def set_cmd(payload: dict) -> dict:
    """POST a goform command with the anti-tamper AD value the UI attaches."""
    # AD = SHA256(SHA256(wa_inner_version + cr_version) + RD), computed fresh
    info = get_cmd(["Language", "cr_version", "wa_inner_version", "RD"])
    ad = sha256_hex(
        sha256_hex(info.get("wa_inner_version", "") + info.get("cr_version", ""))
        + info.get("RD", "")
    )
    return http_request(SET_URL, {**payload, "isTest": "false", "AD": ad}, post=True)


# --------------------------------------------------------------------------
# Router actions
# --------------------------------------------------------------------------
def login(password: str) -> None:
    log(f"Step 1: fetching login token (cmd=LD) from {BASE_URL}")
    ld = get_cmd(["LD"]).get("LD", "")
    if not ld:
        raise RouterError("Router returned an empty LD token - login not possible.")
    log("Step 2: hashing password (SHA256(SHA256(password) + LD)) and posting LOGIN")
    hashed = sha256_hex(sha256_hex(password) + ld)
    # LOGIN must not carry the AD parameter (the web UI excludes it).
    resp = http_request(
        SET_URL,
        {"isTest": "false", "goformId": "LOGIN", "password": hashed},
        post=True,
    )
    result = str(resp.get("result", ""))
    log(f"Step 3: login result code = {result!r} "
        f"({LOGIN_RESULT_MESSAGES.get(result, 'login failed')})")
    if result not in ("0", "4"):
        message = LOGIN_RESULT_MESSAGES.get(result, "login failed")
        # Show the router's own lock state when it can be read.
        log("Reading login lock state (psw_fail_num_str, login_lock_time) ...")
        try:
            lock_info = get_cmd(["psw_fail_num_str", "login_lock_time"])
            log(f"Lock state: {lock_info}")
            if lock_info.get("login_lock_time") not in (None, "", "0"):
                message += (
                    f" Login is currently LOCKED for "
                    f"{lock_info['login_lock_time']}s "
                    f"({lock_info.get('psw_fail_num_str', '?')} failed attempts) - "
                    "wait and try again."
                )
        except (RouterError, KeyError) as exc:
            log(f"Could not read lock state: {exc}")
        raise RouterError(
            f"Login failed (result={result!r}): {message}. "
            "Check that .env holds the admin password used at "
            f"{LOGIN_PAGE_URL} (not the Wi-Fi password)."
        )
    log("Logged in.")


def logout() -> None:
    resp = set_cmd({"goformId": "LOGOUT"})
    if resp.get("result") == "success":
        log("Logged out.")


def read_current_state() -> dict:
    state = get_cmd(["net_select", "sa_nsa_mode_disable_setting"])
    state["sa_nsa_mode_disable_setting"] = (
        state.get("sa_nsa_mode_disable_setting") or SA_MODE_ENABLED
    )
    return state


def apply_network_mode(mode: str, sa_mode: str) -> None:
    """Equivalent of choosing a Preferred Network Type and pressing Apply."""
    log(f"Sending SET_BEARER_PREFERENCE: BearerPreference={mode}, "
        f"sa_nsa_mode_disable_setting={sa_mode}")
    resp = set_cmd(
        {
            "goformId": "SET_BEARER_PREFERENCE",
            "BearerPreference": mode,
            "sa_setting_flag": "true",
            "sa_nsa_mode_disable_setting": sa_mode,
        }
    )
    if resp.get("result") != "success":
        raise RouterError(f"Applying network mode {mode!r} failed: {resp}")
    log(f"Router accepted {mode!r} (result=success).")


def apply_with_retry(mode: str, sa_mode: str) -> None:
    """Apply a network mode, retrying while the router refuses it.

    The router can answer {"result":"failure"} while the modem is still
    re-registering from a previous switch, so retry until both the router
    accepts the command and net_select reflects it.
    """
    for attempt in range(1, APPLY_RETRIES + 1):
        log(f"Apply attempt {attempt}/{APPLY_RETRIES} ...")
        try:
            apply_network_mode(mode, sa_mode)
            wait_for_mode(mode, POLL_TIMEOUT)
            return
        except RouterError as exc:
            log(f"Attempt {attempt} failed: {exc}")
            if attempt < APPLY_RETRIES:
                log(f"Retrying in {APPLY_RETRY_WAIT}s ...")
                time.sleep(APPLY_RETRY_WAIT)
    raise RouterError(
        f"Could not apply network mode {mode!r} after {APPLY_RETRIES} attempts."
    )


def wait_for_mode(target: str, timeout: float) -> None:
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        current = get_cmd(["net_select"]).get("net_select")
        if current == target:
            log(f"Poll {attempt}: net_select == {target!r} - change confirmed.")
            return
        log(f"Poll {attempt}: net_select == {current!r}, waiting for {target!r} ...")
        time.sleep(POLL_INTERVAL)
    raise RouterError(f"Network type did not change to {target} within {timeout:.0f}s")


# --------------------------------------------------------------------------
# .env handling
# --------------------------------------------------------------------------
def load_env(path: str) -> dict:
    env = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def get_password() -> str:
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ENV_FILE)
    env = load_env(env_path)
    password = os.environ.get(ENV_PASSWORD_KEY) or env.get(ENV_PASSWORD_KEY, "")
    if not password:
        raise RouterError(
            f"Set {ENV_PASSWORD_KEY} in {env_path} (see .env.example)."
        )
    return password


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reset the mobile connection by toggling Preferred Network Type."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="login and show what would be done, without changing anything",
    )
    args = parser.parse_args()

    password = get_password()
    log(f"Router: {BASE_URL} (UI page: {LOGIN_PAGE_URL})")
    log(f"Password loaded from .env: {len(password)} characters")
    log("=== Step A: login ===")
    login(password)
    try:
        log("=== Step B: read current Preferred Network Type ===")
        state = read_current_state()
        current = state["net_select"]
        sa_mode = state["sa_nsa_mode_disable_setting"]
        log(f"Read: net_select={current!r}, "
            f"sa_nsa_mode_disable_setting={sa_mode!r}")

        if current not in (MODE_5G, MODE_4G):
            raise RouterError(
                f"Current Preferred Network Type is {current!r} "
                f"(expected {MODE_5G!r} or {MODE_4G!r}) - aborting."
            )

        # The other mode is the temporary one we toggle through.
        other = MODE_4G if current == MODE_5G else MODE_5G
        log(f"Current: {MODE_LABELS[current]} ({current}), "
            f"5G standalone {SA_MODE_LABELS.get(sa_mode, sa_mode)}")
        log(f"Plan: {MODE_LABELS[current]} -> {MODE_LABELS[other]} (Apply) "
            f"-> {MODE_LABELS[current]} (Apply)")

        if args.dry_run:
            log("Dry run - nothing changed.")
            return 0

        # --- 1st Apply: switch to the other technology -----------------------
        # Like the UI, 4G Only forces 5G standalone off; when going back to
        # 5G we restore the SA setting that was active before the toggle.
        temp_sa = SA_MODE_DISABLED if other == MODE_4G else sa_mode
        log(f"=== Step C: 1st Apply - switch to {MODE_LABELS[other]} ===")
        apply_with_retry(other, temp_sa)
        log(f"Set to {MODE_LABELS[other]}. Waiting {SETTLE_SECONDS}s for the "
            "modem to re-register ...")
        time.sleep(SETTLE_SECONDS)

        # --- 2nd Apply: switch back to the original technology ---------------
        final_sa = SA_MODE_DISABLED if current == MODE_4G else sa_mode
        log(f"=== Step D: 2nd Apply - restore {MODE_LABELS[current]} ===")
        apply_with_retry(current, final_sa)
        log(f"Restored to {MODE_LABELS[current]}.")

        # --- Verify ----------------------------------------------------------
        log("=== Step E: verify final state ===")
        final_state = read_current_state()
        log(f"Read: net_select={final_state['net_select']!r}, "
            f"sa_nsa_mode_disable_setting={final_state['sa_nsa_mode_disable_setting']!r}")
        log(f"Final Preferred Network Type: "
            f"{MODE_LABELS.get(final_state['net_select'], final_state['net_select'])}, "
            f"5G standalone "
            f"{SA_MODE_LABELS.get(final_state['sa_nsa_mode_disable_setting'], '?')}")
        if final_state["net_select"] != current:
            raise RouterError(
                f"Final network type {final_state['net_select']!r} does not match "
                f"the original {current!r}."
            )
        log("Done - connection reset.")
        return 0
    finally:
        if LOGOUT_WHEN_DONE:
            log("=== Step F: logout ===")
            try:
                logout()
            except RouterError as exc:
                log(f"Warning: logout failed: {exc}")
        else:
            log("Keeping session logged in (LOGOUT_WHEN_DONE=False).")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RouterError as exc:
        log(f"ERROR: {exc}")
        sys.exit(1)
