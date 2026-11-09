# Speed Wi-Fi HOME 5G L13 - Auto Refresh / 4G-5G Switch

A small Python script that talks directly to the web API of a
**Speed Wi-Fi HOME 5G L13** router (`http://192.168.0.1`) to manage its
mobile connection:

- **Refresh the connection** (default): toggles the *Preferred Network Type*
  through the other technology and back (`5G -> 4G -> 5G` or
  `4G -> 5G -> 4G`), which forces the modem to re-register.
- **Switch to 4G or 5G** on demand with `--mode 4g` / `--mode 5g`.
- **Show the current status** (network type + 5G standalone state) with
  `--status`.

No third-party packages are required - only the Python standard library.

## Requirements

- Python 3.8+
- A computer on the same network as the router (default `192.168.0.1`)
- The router's **admin password** (the one used to log in at
  `http://192.168.0.1/index.html`, not the Wi-Fi password)

## Setup

```sh
cp .env.example .env
# then edit .env and set:
# ROUTER_PASSWORD=your_router_password_here
```

The real `.env` file is ignored by git, so your password is never committed.

## Usage

```sh
# Refresh the connection (toggle through the other technology and back)
python reset_network_type.py

# Switch straight to 5G Preferred
python reset_network_type.py --mode 5g

# Switch straight to 4G Only
python reset_network_type.py --mode 4g

# Only show the current status, change nothing
python reset_network_type.py --status

# Preview what would happen without changing anything
python reset_network_type.py --dry-run
python reset_network_type.py --mode 4g --dry-run
```

Each run logs the **current status** right after login, for example:

```
Status: Preferred Network Type: 5G Preferred (LTE_AND_5G), 5G standalone: enabled
```

If the router is already in the requested mode, `--mode` reports
`nothing to do` and exits without touching the connection.

### Options

| Option | Description |
| --- | --- |
| `--mode {4g,5g}` | Switch directly to `4G Only` or `5G Preferred` instead of toggling. |
| `--status` | Log in, print the current network type / 5G standalone state, exit. |
| `--dry-run` | Log in and show the plan, but change nothing. |

`--status` cannot be combined with `--mode` or `--dry-run`.

## How it works

The router's web UI is JavaScript on top of a JSON `goform` HTTP API:

- `GET /goform/goform_get_cmd_process` - read settings (`net_select`,
  `sa_nsa_mode_disable_setting`, ...)
- `POST /goform/goform_set_cmd_process` - log in / apply settings

Login uses `SHA256(SHA256(password) + LD)`, and every other write request
carries an anti-tamper `AD` value derived from the router's version strings
and `RD`. Applying a network type sends `SET_BEARER_PREFERENCE` with
`BearerPreference=LTE_AND_5G` (5G Preferred) or `Only_LTE` (4G Only);
selecting 4G forces 5G standalone off, like the UI does.

Values of `net_select`:

| Router value | Meaning |
| --- | --- |
| `LTE_AND_5G` | 5G Preferred |
| `Only_LTE` | 4G Only |
| `Only_5G` | 5G SA |

## Exit codes

- `0` - success (including "already in the requested mode" and `--status`)
- `1` - router/network/login error (details are logged)

## Notes

- The router may refuse an Apply while the modem is still re-registering;
  the script retries automatically.
- A refresh can briefly interrupt the mobile connection (typically tens of
  seconds) while the modem re-registers.
- `LOG_HTTP` in the script controls request/response logging. Passwords and
  tokens are always shown hashed, never in plaintext.
