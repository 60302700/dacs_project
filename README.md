# dacs_project

```bash
git clone https://github.com/60302700/dacs_project.git
python -m venv dacs_project
pip install -r requirments.txt
source activate
```
# TODO
- Use TinyDB For The System Cause Why is the Users and rest of data only in ram?


- [ ] Phase 1: Client–Server Communication Setup
Build a basic local client and server that can register a user and attempt a login using
simple request/response APIs. The goal is just to get the communication and local user
storage working (no real crypto yet).

- [ ] Phase 2: Symmetric Protection of Local Secrets
On the client, generate a placeholder secret and store it encrypted with AES (e.g. AES256). Decrypt it only in memory when needed. This establishes secure local storage for
private credentials.

- [ ] Phase 3: Key Pair Generation and Registration
Have the client generate a real public/private key pair. Keep the private key locally
(encrypted with AES from Phase 2). Send only the public key to the server and
associate it with the user/device. The server now knows who you are by public key, not
password.

- [ ] Phase 4: Passwordless Challenge–Response Login
Implement the real login flow: the server sends a random challenge; the client signs it
with its private key; the server verifies the signature using the stored public key. No
password is ever transmitted or stored.

- [ ] Phase 5: Integrity / Device Binding with Hashing
When a device registers, the server stores its public key and device info, and also
stores a hash (e.g. SHA-256) of that record. On later logins, the server re-checks the
hash to detect unauthorized changes.

- [ ] Phase 6: Multi-Device & Revocation
Allow users to register multiple devices (each with its own key pair), view active devices,
and revoke a lost/stolen device so it can no longer authenticate. Prepare final demo,
documentation, and threat model.



