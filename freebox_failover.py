#!/bin/python
"""Freebox failover gateway helper

This daemon watches the WAN state of a Freebox and, when the fiber link goes
DOWN, temporarily takes over as the LAN default gateway using:

- IPv4: Gratuitous ARP + ARP replies to claim the gateway IPv4 address
- IPv6: Unsolicited Neighbor Advertisements and periodic Router Advertisements
        (RA) that announce a default route and a temporary prefix for SLAAC

When the Freebox comes back UP, it withdraws its IPv6 route (RA with lifetime 0),
re-announces the Freebox MAC/addresses, and restores normal operation.

Configuration is read from "/etc/freebox_failover.conf".
"""
import os, sys
import requests, json
import hashlib, hmac
import time, threading
from datetime import datetime
from scapy.all import (
    get_if_hwaddr, Ether, ARP, sendp, conf, sniff, in6_getifaddr,
    IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6NDOptMTU,
    ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS
)
import ipaddress
import ping3
import urllib.parse, urllib.request
import argparse
import configparser

ping3.EXCEPTIONS = True

APP_ID		= "free_wifi_gateway"
APP_NAME	= "Free Wifi Gateway"
APP_VERSION	= "0.0.1"
DEVICE_NAME	= "linux"

failover_active = threading.Event()
stop_thread	= threading.Event()

def timestamp():
    """Create an ISO-like timestamp"""
    return f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"

parser = argparse.ArgumentParser(
    description="Freebox Failover Daemon - monitors Freebox WAN state and "
                "activates 4G failover gateway on outage."
)

parser.add_argument(
    "-c", "--config",
    default="/etc/freebox_failover.conf",
    help="Path to configuration file (default: /etc/freebox_failover.conf)"
)

parser.add_argument(
    "-t", "--token-file",
    default=None,
    help="Path to Freebox app token JSON file (overrides 'token_file' in config)."
)

parser.add_argument(
    "-l", "--log-output",
    choices=["stdout", "stderr", "journald"],
    default="stdout",
    help="here to send logs: stdout, stderr or journald (default: stdout)"
)

args = parser.parse_args()

if args.log_output == "journald":
    from systemd import journal

    journald = journal.stream(APP_NAME)

    def log(msg):
        print(msg, file=journald)
elif args.log_output == "stderr":
    import sys

    def log(msg):
        print(f"{timestamp()} {msg}", file=sys.stderr)
else:
    def log(msg):
        print(f"{timestamp()} {msg}")

if not os.path.exists(args.config):
    log(f"Configuration file {args.config} does not exist.")
    sys.exit(1)

config = configparser.ConfigParser()
config.read(args.config)

FREEMOBILE_USER = config['SMS']['user']
FREEMOBILE_PASS = config['SMS']['pass']
TOKEN_FILE	= args.token_file or config['freebox']['token_file']
LAN_IFACE	= config['freebox']['lan_iface']
FREEBOX_IP = config['freebox']['ip']
FREEBOX_IPV6LL = config['freebox']['ipv6ll']

CHECK_PERIOD_S	= config['failover'].getint('check', fallback=2)
DOWN_THRESHOLD_S= config['failover'].getint('down', fallback=6)
UP_THRESHOLD_S	= config['failover'].getint('up', fallback=10)
GARPS_EVERY_S   = config['failover'].getint('garp', fallback=3)

FAILOVER_PREFIX = config.get('ipv6', 'prefix', fallback='fd00:1234::/64').strip()
RDNSS_LIST = [s for s in config.get('ipv6', 'rdnss', fallback='').split() if s]
ROUTER_LIFETIME = config['ipv6'].getint('router_lifetime', fallback=30)

API_URL		= f"http://{FREEBOX_IP}/api/v8"

def check_connectivity(host="8.8.8.8", count=1, timeout=0.5):
    """Use ping to check backup connectivity"""
    try:
        reply = ping3.ping(host, timeout=timeout)
    except ping3.errors.PingError as exc:
        log(f"Connectivity check error: {exc}")
        return False
    log(f"Connectivity check succeeded to {host}")
    return True

def send_SMS(message):
    """Send an SMS notification via the Free Mobile SMS API.

    Parameters
    ----------
    message : str
        The text to send.

    Side Effects
    ------------
    Performs an HTTPS GET to Free Mobile's API. Logs an error to journald
    if the request fails.
    """
    try:
        payload = { 'user': FREEMOBILE_USER, 'pass': FREEMOBILE_PASS, 'msg': message }
        params = urllib.parse.urlencode(payload, quote_via=urllib.parse.quote)
        urllib.request.urlopen('https://smsapi.free-mobile.fr/sendmsg?%s' % params, timeout=5)
    except Exception as e:
        log(f"SMS send failed: {e}")


def load_app_token():
    """Load persisted Freebox application token and track_id from disk.

    Returns
    -------
    tuple[str|None, str|None]
        (app_token, track_id) if present; (None, None) otherwise.
    """
    if not os.path.exists(TOKEN_FILE):
        return None, None

    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data["app_token"], data["track_id"]
    except (json.JSONDecodeError, KeyError) as exc:
        log(f"Token file invalid ({TOKEN_FILE}): {exc}. Delete and re-register.")
    except OSError as exc:
        log(f"Could not read token file {TOKEN_FILE}: {exc}")

    return None, None

def api_request(method, endpoint, session_token=None, **kwargs):
    """Call a Freebox OS API endpoint and return its `result` payload.

    Parameters
    ----------
    method : str
        HTTP verb, e.g. 'get', 'post'.
    endpoint : str
        API path beginning with '/'.
    session_token : str | None
        Optional session token to send as 'X-Fbx-App-Auth'.
    **kwargs : dict
        Extra arguments forwarded to `requests.request` (json=data, params, etc.).

    Returns
    -------
    Any | str | None
        The `result` field on success; the string 'forbidden' on HTTP 403;
        or None on network/JSON errors.

    Side Effects
    ------------
    Logs API/network/JSON errors to journald.
    """
    headers = {}
    if session_token:
        headers["X-Fbx-App-Auth"] = session_token

    try:
        response = requests.request(method, f"{API_URL}{endpoint}", headers=headers,
                                    timeout=5, **kwargs)
        response.raise_for_status()
        data = response.json()
        if data.get('success'):
            return data.get('result')
        else:
            log(f"API Error on {endpoint}: {data.get('msg')}")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            return "forbidden" # Return a special string for 403 errors
        else:
            log(f"HTTP Error on {endpoint}: {e}")
    except requests.exceptions.RequestException as e:
        log(f"Network Error on {endpoint}: {e}")
    except json.JSONDecodeError:
        log(f"JSON Decode Error on {endpoint}")
    return None

def freebox_connect():
    """Establish a Freebox OS API session token.

    1) Load stored app token/track_id from the token file; fail if absent.
    2) Compute HMAC-SHA1 password from challenge and app_token.
    3) Open a login session and return the session token.

    Returns
    -------
    str | None
        A valid session token, or None if the flow fails.

    Side Effects
    ------------
    Logs status messages to journald.
    """
    app_token, track_id = load_app_token()
    if not app_token or not track_id:
        log("App token missing. Run freebox_failover_register.py before starting.")
        return None

    challenge_data = api_request("get", f"/login/authorize/{track_id}")
    if challenge_data == "forbidden":
        log("Freebox rejected stored app token (403). Delete token file and re-register.")
        return None
    if not challenge_data or not isinstance(challenge_data, dict):
        log("Failed to get challenge, token might be invalid.")
        return None
    challenge = challenge_data.get('challenge')
    if not challenge:
        log("Challenge missing from Freebox response.")
        return None

    password = hmac.new(app_token.encode(), challenge.encode(), hashlib.sha1).hexdigest()

    login_data = api_request("post", "/login/session/",
                             json={"app_id": APP_ID, "password": password})
    if login_data == "forbidden":
        log("Login forbidden – app token probably revoked. Re-register and retry.")
        return None
    if not isinstance(login_data, dict):
        log("Unexpected login response format.")
        return None

    return login_data.get('session_token')

def freebox_get_link_state(session_token):
    """Return the WAN link state string from the Freebox.

    Parameters
    ----------
    session_token : str
        Active session token from `freebox_connect()`.

    Returns
    -------
    str | None
        'up', 'down', 'going_up', etc., 'forbidden' when 403, or None on error.
    """
    status = api_request("get", "/connection/", session_token)

    if isinstance(status, dict) and 'state' in status:
        return status['state']

    return status

def freebox_get_hwaddr(session_token):
    """Get the Freebox system MAC address.

    Parameters
    ----------
    session_token : str
        Active session token.

    Returns
    -------
    str | None
        MAC address string like 'aa:bb:cc:dd:ee:ff', or None on error.
    """
    system_info = api_request("get", "/system/", session_token)
    return system_info['mac'] if system_info else None

def freebox_get_ip(session_token):
    """Get the Freebox LAN IPv4 gateway address.

    Parameters
    ----------
    session_token : str
        Active session token.

    Returns
    -------
    str | None
        IPv4 address string of the LAN gateway, or None on error.
    """
    lan_config = api_request("get", "/lan/config/", session_token)
    return lan_config['ip'] if lan_config else None

def freebox_get_ipv6_ll(session_token):
    """Retrieve the Freebox's link-local IPv6 address, with fallback to config.

    Parameters
    ----------
    session_token : str
        Active session token.

    Returns
    -------
    str | None
        The Freebox link-local IPv6 (fe80::/10) or None if not available.
    """
    lan_config = api_request("get", "/connection/ipv6/config/", session_token)

    if not lan_config or not lan_config.get('ipv6ll'):
        log(f"No link-local from Freebox, using configuration ({FREEBOX_IPV6LL}")
        return FREEBOX_IPV6LL

    fb_ll = lan_config.get("ipv6ll")

    if FREEBOX_IPV6LL and fb_ll != FREEBOX_IPV6LL:
        log(f"link-local retrieved from Freebox differs from configuration ({fb_ll} != {FREEBOX_IPV6LL})")

    return fb_ll

def my_mac():
    """Return the MAC address of the LAN interface configured in `LAN_IFACE`.

    Returns
    -------
    str
        MAC address string for the LAN interface.
    """
    return get_if_hwaddr(LAN_IFACE)

def send_garp(gateway_ip, mac):
    """Send a burst of Gratuitous ARP frames claiming the IPv4 gateway IP.

    Parameters
    ----------
    gateway_ip : str
        The IPv4 address to claim on the LAN (Freebox LAN IP).
    mac : str
        The MAC address to advertise as owner of `gateway_ip`.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / \
          ARP(op=2, psrc=gateway_ip, pdst=gateway_ip,
              hwsrc=mac, hwdst="ff:ff:ff:ff:ff:ff")
    sendp(pkt, iface=LAN_IFACE, count=3, inter=0.2, verbose=False)

def send_na(gateway_ipv6, mac):
    """Send unsolicited IPv6 Neighbor Advertisements to claim the gateway IPv6.

    Parameters
    ----------
    gateway_ipv6 : str
        The IPv6 address (often link-local) to claim on the LAN.
    mac : str
        The MAC address to advertise as owner of `gateway_ipv6`.
    """
    pkt = Ether(dst="33:33:00:00:00:01", src=mac) / \
          IPv6(src=gateway_ipv6, dst="ff02::1") / \
          ICMPv6ND_NA(
              tgt=gateway_ipv6,
              R=1, S=0, O=1 # Router flag, not Solicited, Override flag
          ) / \
          ICMPv6NDOptSrcLLAddr(lladdr=mac)
    sendp(pkt, iface=LAN_IFACE, count=3, inter=0.2, verbose=False)

def get_link_local_addr(iface):
    """Return the link-local IPv6 address for a network interface.

    Parameters
    ----------
    iface : str
        Interface name (e.g., 'eth0').

    Returns
    -------
    str | None
        The first fe80::/10 address found on `iface`, or None.

    Notes
    -----
    Uses Scapy's `in6_getifaddr()` which yields tuples (addr, scope, ifname)
    on your environment.
    """
    try:
        for addr, scope, ifname in in6_getifaddr():
            if ifname == iface and addr.lower().startswith("fe80:"):
                # Keep as 'fe80::...' (scope will be set via 'dev iface' on sendp)
                return addr
    except Exception as e:
        log(f"in6_getifaddr() failed on {iface}: {e}")
    return None

def build_ra_pkt(iface, src_ll, lladdr, router_lifetime, advertise_prefix=None, rdnss_list=None):
    """Construct a Router Advertisement packet for ff02::1 with optional options.

    Parameters
    ----------
    iface : str
        LAN interface name packets will be sent on.
    src_ll : str
        Link-local IPv6 used as the source address of the RA.
    lladdr : str
        Source link-layer (MAC) address to advertise in SLLAO.
    router_lifetime : int
        Default-route lifetime in seconds (0 withdraws default route).
    advertise_prefix : str | None
        Optional IPv6 prefix (e.g., 'fd00:1234::/64') to include as a PIO for SLAAC.
    rdnss_list : list[str] | None
        Optional list of recursive DNS server IPv6 addresses to advertise.

    Returns
    -------
    scapy.packet.Packet
        The fully-constructed RA `Packet` ready to send with `sendp`.
    """
    ra = (Ether(dst="33:33:00:00:00:01", src=lladdr) /
          IPv6(src=src_ll, dst="ff02::1") /
          ICMPv6ND_RA(
              chlim=64,
              M=0, O=1,         # SLAAC + provide other config (DNS)
              routerlifetime=router_lifetime,
              prf=1             # high preference while active
          ) /
          ICMPv6NDOptSrcLLAddr(lladdr=lladdr) /
          ICMPv6NDOptMTU(mtu=1500))

    # Prefix Information Option (PIO)
    if advertise_prefix:
        net = ipaddress.ip_network(advertise_prefix, strict=False)
        if net.version == 6:
            ra = ra / ICMPv6NDOptPrefixInfo(
                prefixlen=net.prefixlen,
                L=1, A=1,           # on-link + autonomous (SLAAC)
                validlifetime=180,  # shortish; we re-announce frequently
                preferredlifetime=90,
                prefix=str(net.network_address)
            )

    # Recursive DNS Server Option (RDNSS)
    if rdnss_list:
        # lifetime should not exceed router_lifetime too much
        ra = ra / ICMPv6NDOptRDNSS(lifetime=max(router_lifetime, 30),
                                   dns=rdnss_list[:3]) # up to 3 per RFC

    return ra

def send_ra(iface, src_ll, lladdr, router_lifetime, advertise_prefix=None, rdnss_list=None, burst=3):
    """Send a burst of Router Advertisements on the LAN.

    Parameters
    ----------
    iface : str
        LAN interface to transmit on.
    src_ll : str
        Source link-local IPv6 for the RA.
    lladdr : str
        Source MAC (SLLAO) for the RA.
    router_lifetime : int
        Default-route lifetime in seconds.
    advertise_prefix : str | None
        Optional prefix to include as PIO (for SLAAC addresses).
    rdnss_list : list[str] | None
        Optional recursive DNS servers to include as RDNSS.
    burst : int
        Number of RAs to send in quick succession (spacing 0.2s).
    """
    pkt = build_ra_pkt(iface, src_ll, lladdr, router_lifetime, advertise_prefix, rdnss_list)
    sendp(pkt, iface=iface, count=burst, inter=0.2, verbose=False)

def send_ra_zero_lifetime(iface, src_ll, lladdr):
    """Withdraw default route and quickly deprecate SLAAC addresses.

    Sends an RA with `router_lifetime=0` (removes default route) and a PIO for
    the configured `FAILOVER_PREFIX` where `preferredlifetime=0` and
    `validlifetime=5`, prompting clients to stop using the temporary addresses
    quickly.

    Parameters
    ----------
    iface : str
        LAN interface name.
    src_ll : str
        Source link-local IPv6 used in the RA.
    lladdr : str
        Source MAC address used in the RA.
    """
    # Also include PIO with zero preferred lifetime to quickly deprecate addr
    zero_ra = build_ra_pkt(
        iface, src_ll, lladdr,
        router_lifetime=0,
        advertise_prefix=f"{FAILOVER_PREFIX}",  # same prefix
        rdnss_list=None
    )
    # overwrite PIO lifetimes to force deprecate
    for layer in zero_ra.payload.payload.payload.iterpayloads():
        if isinstance(layer, ICMPv6NDOptPrefixInfo):
            layer.preferredlifetime = 0
            layer.validlifetime = 5
    sendp(zero_ra, iface=iface, count=3, inter=0.2, verbose=False)

def manage_failover_networking(gateway_ip, gateway_ipv6):
    """Run the L2 takeover logic and packet responders on the LAN.

    Starts an announcer thread that periodically sends GARP/NA and RAs when
    failover is active, and listens for ARP/NDP requests to answer them while
    acting as the temporary gateway.

    Parameters
    ----------
    gateway_ip : str
        The Freebox LAN IPv4 gateway address.
    gateway_ipv6 : str | None
        The Freebox LAN IPv6 gateway address (often link-local). May be None.

    Side Effects
    ------------
    Spawns a daemon thread and starts a `scapy.sniff()` loop until `stop_thread`
    is set. Logs activity to journald.
    """
    conf.sniff_promisc = True
    log(f"Network handler started for IPv4 ({gateway_ip}) and IPv6 ({gateway_ipv6})")

    my_hwaddr = my_mac()

    def handle_requests(pkt):
        """Respond to ARP who-has and IPv6 Neighbor Solicitations during failover."""
        if not failover_active.is_set():
            return

        # IPv4: ARP "who-has" request
        if ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].pdst == gateway_ip:
            # who-has gateway_ip? Tell <my_mac>
            reply = Ether(dst=pkt[Ether].src, src=my_hwaddr) / \
                    ARP(op=2, psrc=gateway_ip, pdst=pkt[ARP].psrc,
                        hwsrc=my_hwaddr, hwdst=pkt[ARP].hwsrc)
            sendp(reply, iface=LAN_IFACE, verbose=False)

        # IPv6: Neighbor Solicitation request
        elif ICMPv6ND_NS in pkt and pkt[ICMPv6ND_NS].tgt == gateway_ipv6:
            reply = Ether(dst=pkt[Ether].src, src=my_hwaddr) / \
                    IPv6(src=gateway_ipv6, dst=pkt[IPv6].src) / \
                    ICMPv6ND_NA(tgt=gateway_ipv6, R=1, S=1, O=1) / \
                    ICMPv6NDOptSrcLLAddr(lladdr=my_hwaddr)
            sendp(reply, iface=LAN_IFACE, verbose=False)

    def announcer():
        """Periodically announce ARP/NA and send RAs while in failover mode."""
        src_ll = get_link_local_addr(LAN_IFACE)
        if not src_ll:
            log(f"Could not find link-local IPv6 on {LAN_IFACE}; RAs disabled.")

        while not stop_thread.is_set():
            if failover_active.is_set():
                send_garp(gateway_ip, my_hwaddr)
                if gateway_ipv6:
                    send_na(gateway_ipv6, my_hwaddr)

                # send RA to advertise default route + prefix during failover
                if src_ll:
                    try:
                        send_ra(
                            iface=LAN_IFACE,
                            src_ll=src_ll,
                            lladdr=my_hwaddr,
                            router_lifetime=ROUTER_LIFETIME,
                            advertise_prefix=FAILOVER_PREFIX,
                            rdnss_list=RDNSS_LIST
                        )
                    except Exception as e:
                        log(f"RA send error: {e}")

            stop_thread.wait(GARPS_EVERY_S)

    announcer_thread = threading.Thread(target=announcer, daemon=True)
    announcer_thread.start()

    # Sniff for both ARP (IPv4) and ICMPv6 (for NDP) packets
    sniff(iface=LAN_IFACE, filter="arp or icmp6", prn=handle_requests, store=False, \
          stop_filter=lambda p: stop_thread.is_set())

    log("Network handler stopped")

def switch_to_backup_gateway(reason):
    """
    Activate the backup (failover) gateway.

    This marks the failover gateway as active so that the announcer
    thread will begin sending gratuitous ARP, IPv6 Neighbor Advertisements,
    and Router Advertisements to impersonate the Freebox on the LAN.

    Parameters
    ----------
    reason : str
        Human-readable reason for switching (e.g., "Freebox DOWN").
        Included in the log output.
    """
    log(f"Switch to backup gateway ({reason})")
    failover_active.set()

def switch_to_primary_gateway(freebox_ip, freebox_ipv6, freebox_hwaddr, reason):
    """
    Restore the Freebox as the primary gateway.

    This clears the failover state so the announcer stops impersonating
    the Freebox, and re-announces the Freebox’s own addresses to clients:

      • Sends gratuitous ARP (GARP) so clients quickly relearn the Freebox’s MAC
        as the IPv4 gateway.
      • Sends IPv6 Neighbor Advertisements (NA) if a link-local IPv6 is available.
      • Sends Router Advertisements (RA) with zero lifetimes to withdraw the
        previously advertised failover prefix and default route, prompting
        clients to fall back to the Freebox.
      • Logs the reason for the switch.

    Parameters
    ----------
    freebox_ip : str
        Freebox IPv4 gateway address to restore.
    freebox_ipv6 : str or None
        Freebox link-local IPv6 address to restore, if available.
    freebox_hwaddr : str
        MAC address of the Freebox.
    reason : str
        Human-readable reason for switching (e.g., "Freebox UP").
        Included in the log output.
    """
    log(f"Switch to primary gateway ({reason})")
    failover_active.clear()
    send_garp(freebox_ip, freebox_hwaddr)
    if freebox_ipv6:
        send_na(freebox_ipv6, freebox_hwaddr)
        try:
            src_ll = get_link_local_addr(LAN_IFACE)
            if src_ll:
                send_ra_zero_lifetime(LAN_IFACE, src_ll, my_mac())
        except Exception as e:
            log(f"RA withdraw error: {e}")
    log("Announced Freebox MAC to hand back quickly")

def main():
    """Entry point: monitor Freebox link state and toggle failover behavior.

    Workflow
    --------
    - Authenticate to the Freebox and obtain a session token.
    - Read gateway addresses and start the LAN networking helper thread.
    - Poll `/connection/` periodically:
        * When state transitions to DOWN for `DOWN_THRESHOLD_S`, enable failover
          (set event, send SMS, start announcing).
        * When back to UP for `UP_THRESHOLD_S`, withdraw RAs, restore Freebox
          as gateway (GARP/NA), and send SMS.

    Side Effects
    ------------
    Runs indefinitely until interrupted; logs to journald; sends SMS alerts.
    """

    if not check_connectivity():
        log("Connectivity check failed, exiting.")
        return

    session_token = freebox_connect()
    if not session_token:
        log("Could not connect to Freebox. Exiting.")
        return

    freebox_hwaddr = freebox_get_hwaddr(session_token)
    freebox_ip = freebox_get_ip(session_token)
    freebox_ipv6 = freebox_get_ipv6_ll(session_token)
    if not all([freebox_hwaddr, freebox_ip]):
        log("Could not retrieve Freebox network details. Exiting.")
        return

    log(f"Starting failover monitor on {LAN_IFACE} (gw4={freebox_ip}, gw6={freebox_ipv6 or 'N/A'})")

    net_thread = threading.Thread(
        target=manage_failover_networking,
        daemon=True,
        args = (freebox_ip, freebox_ipv6) )
    net_thread.start()

    down_since = None
    up_since = None

    try:
        while True:
            state = freebox_get_link_state(session_token)
            now = time.time()

            if state == "forbidden":

                new_token = freebox_connect()
                if new_token:
                    session_token = new_token
                else:
                    log("Failed to re-login. Exiting; re-register token first.")
                    break

                time.sleep(CHECK_PERIOD_S * 2)
                continue

            if state == "up":
                up_since = up_since or now
                down_since = None
                if failover_active.is_set() and (now - up_since) >= UP_THRESHOLD_S:
                    log("Freebox back UP")
                    switch_to_primary_gateway(freebox_ip, freebox_ipv6, freebox_hwaddr, "Up")
                    send_SMS("Freebox back UP")
            else:
                down_since = down_since or now
                up_since = None
                if not failover_active.is_set() and (now - down_since) >= DOWN_THRESHOLD_S:
                    log(f"Freebox DOWN (state {state})")
                    switch_to_backup_gateway("Down")
                    send_SMS(f"Freebox DOWN (state {state})")

            time.sleep(CHECK_PERIOD_S)
    except KeyboardInterrupt:
        log("Stopping (SIGINT)")
    finally:
        stop_thread.set()
        if failover_active.is_set():
            log("Handing back gateway control on exit.")
        switch_to_primary_gateway(freebox_ip, freebox_ipv6, freebox_hwaddr, "Exit");

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("ERROR: this script must be run as root. Try: sudo " + " ".join(sys.argv))

    conf.verb = 0
    main()
