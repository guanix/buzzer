#!/usr/bin/env python

from __future__ import print_function
import socket, hashlib, hmac, types, struct, time, sys

# We should switch this to CoAP once Guan writes a CoAP stack for Lua

# WARNING: These are Lua 1-based indices
# 1. client-to-server: request challenge
#      byte 1:     1
#      byte 2:     1 (for unlock)
#      bytes 3-22: (binary) hash of the SHARED secret
# 2. server-to-client: respond with challenge
#      byte 1:     2
#      byte 2:     1 (for unlock)
#      bytes 3-6:  timestamp (unix time_t)
#      bytes 7-10:  sequence number
#      bytes 11-30: challenge
#      the challenge is the HMAC of the SERVER secret and:
#          4-byte timestamp (network byte order)
#          4-byte sequence number (network byte order)
#          1-byte command 1 (for unlock)
#      (this is a stateless protocol)
# 3. client-to-server: respond to challenge
#      byte 1:     3
#      byte 2:     1 (for unlock)
#      bytes 3-22: (binary) hash of the SHARED secret
#      bytes 23-26:  timestamp (unix time_t)
#      bytes 27-30:  sequence number
#      bytes 31-50: hmac of challenge with SHARED secret
# 4. server-to-client: op successful
#      byte 1:     4
#      byte 2:     1
#      byte 3-6:   timestamp
#      byte 7-10:  sequence number
#      bytes 11-30: hmac with SHARED secret of:
#          4-byte timestamp
#          4-byte sequence number
#          1-byte command


def sha1(text):
    return hashlib.sha1(text).digest()

def sha1_hmac(text, secret):
    return hmac.new(secret, text, hashlib.sha1).digest()

class Buzzer():
    def __init__(self, our_secret, shared_secrets):
        assert type(our_secret) == str
        assert type(shared_secrets) == list

        self.our_secret = our_secret
        self.shared_secrets = shared_secrets
        self.seq = 0

        self.shared_secrets_hashed = {
            sha1(shared_secret): shared_secret
            for shared_secret in shared_secrets
        }

    def increment(self):
        self.seq += 1

    def compute_challenge(self, t, seq, cmd):
        text = struct.pack("!iiB", t, seq, cmd)
        return sha1_hmac(text, self.our_secret)

    def handle_packet(self, data, respond, action=None):
        assert type(respond) == types.FunctionType

        # Packets are always less than 22 bytes
        if len(data) < 22: return false

        op = ord(data[0])
        cmd = ord(data[1])

        # We only support one command right now
        if cmd != 1:
            print("invalid command")
            return False

        # All the current messages have the hash of the shared secret as
        # bytes 3-22 (2-21)
        msg_shared_secret_hash = data[2:22]
        shared_secret = self.shared_secrets_hashed.get(msg_shared_secret_hash)
        if not shared_secret:
            print("shared secret not found")
            return False

        print("shared secret found")

        if op == 1 and len(data) == 22:
            print("request challenge")
            return self.handle_challenge(data, cmd, respond)
        elif op == 3 and len(data) == 50:
            print("challenge response")
            return self.handle_response(data, cmd, shared_secret, respond, action)
        else:
            print("invalid, op", op, "len", len(data))

    def handle_response(self, data, cmd, shared_secret, respond, action):
        current_time = int(float(time.time()))
        (t, seq) = struct.unpack("!ii", data[22:30])
        challenge = self.compute_challenge(t, seq, cmd)
        challenge_hash = sha1_hmac(challenge, shared_secret)
        if challenge_hash != data[30:50]:
            print("hash incorrect")
            return False

        print("hash correct")

        # Send a response saying we were successful
        response_text = struct.pack("!iiB", t, seq, cmd)
        response_hash = sha1_hmac(response_text, shared_secret)
        response = chr(4) + chr(cmd) + struct.pack("!ii", t, seq) + response_hash
        respond(response)

        print("performing action")
        action()
        return True

    def handle_challenge(self, data, cmd, respond):
        # Increment sequence number
        self.increment()

        # Calculate the challenge
        t = int(float(time.time()))
        challenge = self.compute_challenge(t, self.seq, cmd)

        response = chr(2) + chr(cmd) + struct.pack("!ii", t, self.seq) + challenge
        respond(response)
        return True

    def listen(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))
        print("listening")

        while True:
            data, addr = sock.recvfrom(1024)
            print("received", addr)
            self.handle_packet(data,
                lambda response: sock.sendto(response, addr),
                lambda: print("action!"))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("%s our_secret shared_secret1 [shared_secret2 ..]" % sys.argv[0],
            file=sys.stderr)
    buzzer = Buzzer(sys.argv[1], sys.argv[2:])
    buzzer.listen("0.0.0.0", 4242)
