# Pre-Login Connect (Windows)

Pre-Login Connect lets a user connect the VPN from the Windows sign-in screen, before they sign
in. It's useful when signing in itself needs the corporate network:

- the first sign-in of a domain account on a laptop
- group policy and drive mappings that are applied during sign-in
- sign-in scripts

The connection is offered through Windows' standard **Network sign-in** button. Comparable
products, such as OpenVPN Connect's PLC, use the same entry point.

> **Status:** in development (feature 003). The service side already works: sign-in
> profiles, the sign-out policy, administrator checks, and the `plc` and `profile import`
> commands. Still to come:
>
> - the sign-in screen component (`ipsec_plap.dll`)
> - its installer feature (`PLC=1`)
>
> Sections that depend on them say so.

## How it works

- The **IPsec VPN Client Service** already owns the VPN tunnel, independently of any user.
  The sign-in screen component only asks the service to connect.
- After the user signs in, their tray app shows the same connection, with its address,
  duration and counters, and they can disconnect it there.
- Only profiles that an administrator has made **available at sign-in** are offered.
- At the sign-in screen, a username/password profile always asks for the password. A saved
  password is never used there, because anyone at the console can reach that screen. The
  pre-shared key stored in the profile is used, because it identifies the organisation, not
  the person.

## Requirements

- Windows 10 22H2, or Windows 11 23H2 or 24H2, on x64.
- The client installed with the Pre-Login Connect feature (see below).
- Network connectivity at the sign-in screen.
  - Wired connections work.
  - **Wi-Fi must be set up for all users.** A Wi-Fi network saved only for one user isn't
    connected before sign-in, and connecting fails with "gateway unreachable".

## Enabling it

Everything below needs an **elevated** prompt (Run as administrator). The service decides who
is an administrator from the Windows token of the calling process. A standard user, or an
administrator in a non-elevated prompt, gets "Administrator rights are required for this
change" and exit code 5.

### 1. Install the feature

*(Available with the installer feature `PLC`, task T025.)*

```bat
msiexec /i IpsecClient-<version>-x64.msi PLC=1
```

For unattended deployment you can also pass:

| Property | Effect |
|----------|--------|
| `PLC_PROFILES_FILE=<path>` | Imports the profiles in that file and makes them available at sign-in |
| `PLC_KEEP_ON_SIGNOUT=1` | Keeps the tunnel when the user signs out (see "Sign-out policy") |

Installing without `PLC=1` leaves the sign-in screen unchanged.

### 2. Choose the profiles offered at sign-in

```bat
ipsec-service plc list                 :: all profiles, sign-in ones marked [sign-in]
ipsec-service plc enable "Office"      :: offer it at sign-in
ipsec-service plc disable "Office"     :: stop offering it
```

Profile names are matched case-insensitively. Renaming a profile keeps its availability, and
deleting it removes it from the sign-in screen too. Users see "(sign-in)" next to these
profiles in the tray app, but can't change it.

### 3. Or import profiles

```bat
ipsec-service profile import C:\deploy\profiles.json --sign-in
```

The file format (UTF-8; a byte-order mark is fine):

```json
{ "profiles": [
  { "name": "Office", "gateway": "vpn.example.com", "port": 500,
    "local_id": "laptop", "id_type": "fqdn", "dh_group": "modp2048",
    "auth": "eap", "username": "", "psk": "…" }
] }
```

- Fields that can be left out:
  - `port` (default 500)
  - `id_type` (`fqdn`, `email` or `ipv4`; default `fqdn`)
  - `dh_group` (`modp2048`, `modp1536` or `x25519`; default `modp2048`)
  - `auth` (`eap` or `psk`; default `eap`)
  - `username`
  - `auto_reconnect`
  - `psk`
  - `password`
- A profile with the same name, compared case-insensitively, is updated. Otherwise a new one
  is created.
- Secrets left out of the file keep their stored value.
- **The file contains the pre-shared key in plain text. Delete it after deployment.** The
  service stores secrets encrypted (DPAPI).

## Using it at the sign-in screen

*(Needs the sign-in component, tasks T014–T018.)*

1. On the sign-in screen, select **Network sign-in**, the icon in the bottom-right corner.
2. Pick the VPN profile. For a username/password profile, type the password; the username is
   filled in from the profile.
3. Select **Connect**. The status shows *Connecting…*, then *Authenticating…*, then
   *Connected*. Errors use the same messages as the tray app, for example *Authentication
   failed: wrong username or password*.
4. Sign in to Windows as usual.

You can cancel while it connects. If a tunnel is already up, Network sign-in shows it as
connected and offers **Disconnect**.

## After sign-in

The tunnel stays up. The tray app shows it as Connected, and the user can disconnect it there
like any other connection.

## Sign-out policy

When the signed-in user **signs out** of Windows, the service by default disconnects the
tunnel, and restores routes and DNS before the sign-in screen returns. That way the next
person at the machine doesn't inherit the previous user's VPN session.

```bat
ipsec-service plc policy                          :: show the current policy
ipsec-service plc policy keep-on-signout          :: keep the tunnel across sign-outs
ipsec-service plc policy disconnect-on-signout    :: the default
```

The policy applies to every tunnel, whether it was started at the sign-in screen or from the
tray app. Locking the workstation, switching users and remote-desktop connects or disconnects
are **not** sign-outs, and leave the tunnel alone. The policy is applied by the installed
service; `ipsec-service run` in a console doesn't receive sign-out notifications.

The policy is stored in `%ProgramData%\IpsecClient\settings.json`.

## Logs

- **Service log:** `%ProgramData%\IpsecClient\logs\service.log.*`. Each connect is logged with
  where it came from and who asked:
  - `origin=app` or `origin=sign_in_screen`
  - the requesting process: `pid=…`, `user=…`, `elevated=…`

  Sign-out disconnects are logged with `reason=signout`, and also appear in the Windows Event
  Log under Application, source `IpsecClient`. Refused administrator requests are logged as
  warnings.
- **Sign-in component log:** `%ProgramData%\IpsecClient\logs\plap.log`, capped at 1 MiB with
  one rollover. *(Comes with the sign-in component.)*

No log contains passwords or pre-shared keys.

## Recovery

If the sign-in screen misbehaves after installing Pre-Login Connect, disable the component.
The VPN service and normal sign-in are not affected.

**If an administrator can still sign in**, choose any of these, from an elevated prompt:

- `ipsec-service plc disable-provider`, which removes the Network sign-in registration
  immediately and works even if the service is stopped
- removing the *Pre-Login Connect* feature in **Settings → Apps**
- uninstalling the client

**If nobody can sign in:**

1. Start Windows Recovery: hold **Shift** while selecting **Restart**, or interrupt the boot
   twice. Then choose **Troubleshoot → Advanced options → Command Prompt**.
2. Remove the registration from the offline registry:

   ```bat
   reg load HKLM\OFFLINE C:\Windows\System32\config\SOFTWARE
   reg delete "HKLM\OFFLINE\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers\{6F1B0E52-3C4A-4D8E-9B61-2A7C5D0E8F13}" /f
   reg unload HKLM\OFFLINE
   ```

   If Windows isn't on `C:` in the recovery environment, find it with `dir D:\Windows` (or E:,
   and so on) and adjust the path.
3. Close the prompt and choose **Continue** to start Windows.

The provider's identifier `{6F1B0E52-3C4A-4D8E-9B61-2A7C5D0E8F13}` never changes between
versions.

## Limitations

- Pre-Login Connect is user-initiated. It isn't an always-on or machine tunnel, and it doesn't
  connect by itself at boot.
- The VPN credentials aren't reused as the Windows sign-in (no single sign-on).
- No MFA, SAML or web sign-in, and no certificate authentication.
- One tunnel per machine. If a tunnel is already active, a second connect is refused with
  "Already connected".
- x64 only.

## Command reference

| Command | Who | Exit codes |
|---------|-----|------------|
| `ipsec-service plc list` | anyone | 0; 1 if the service isn't running |
| `ipsec-service plc enable <name>` / `disable <name>` | administrator | 0; 1 if not found or the service isn't running; 5 if not admin |
| `ipsec-service plc policy [keep-on-signout \| disconnect-on-signout]` | anyone to show; administrator to change | 0; 1; 5 |
| `ipsec-service plc disable-provider` | administrator | 0; 5 |
| `ipsec-service profile import <file> [--sign-in]` | administrator | 0; 1 if a profile is invalid (each is reported); 5 |

The full contract is in
[specs/003-pre-login-connect/contracts/service-cli-plc.md](../specs/003-pre-login-connect/contracts/service-cli-plc.md).
