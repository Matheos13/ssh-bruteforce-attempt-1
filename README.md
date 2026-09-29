# SSH Brute-Force Attempt #1

Author: Matheou13

Python script that tries username/password combos from a wordlist against
an SSH server. Made for a cybersecurity course exercise on credential
brute-forcing.

## Legal notice

Only run this against a system you own or are authorized to test - your
own lab VM, a CTF box, whatever. Don't point it at anything else, that's
illegal (CFAA in the US, similar laws elsewhere) and against pretty much
every school's acceptable use policy. And again this is for educational purposes only.

## Setup

Spin up something to test against. Easiest way is a local Docker SSH
container:

```bash
docker run -d --name ssh-lab -p 2222:22 \
  -e SSH_USERS=student:1001:1001 \
  -e PASSWORD_ACCESS=true \
  -e USER_PASSWORD=lab1234 \
  linuxserver/openssh-server
```

Install deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Edit `wordlists/users.txt` and `wordlists/passwords.txt` if you want, just
make sure the real password is actually in the list or you won't get a hit.

## Running it

```bash
python3 ssh_bruteforce.py --host 127.0.0.1 --port 2222 \
  --user student --wordlist wordlists/passwords.txt --i-am-authorized
```

or with multiple usernames:

```bash
python3 ssh_bruteforce.py --host 127.0.0.1 --port 2222 \
  --userlist wordlists/users.txt --wordlist wordlists/passwords.txt --i-am-authorized
```

`--i-am-authorized` is required on purpose, so it can't accidentally get
run against a random host.

Other flags: `--delay` (seconds between tries, default 1), `--timeout`
(connection timeout, default 5), `--no-stop-on-success` (keep going after
a hit instead of stopping), `--log-file` (where the log goes).

## How it works

Loops through every username/password pair and tries a real SSH connection
with `paramiko`. If it raises `AuthenticationException` the creds were
wrong, if `connect()` succeeds they were right. Everything gets logged to
both the console and the log file. There's a delay between attempts so it
doesn't hammer the target.

## Defenses against this (for the writeup)

- turn off password auth, use keys only (`PasswordAuthentication no`)
- fail2ban / sshguard to lock out after N failed attempts
- don't expose SSH to the internet directly, use a bastion/VPN
- strong password policy if you do need password auth
- monitor auth logs for repeated failures

## License

MIT, see LICENSE file.
