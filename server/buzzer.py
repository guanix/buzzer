#!/usr/bin/env python

from __future__ import print_function
import socket, hashlib, hmac, types, struct, time

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

    def compute_challenge(self, t, cmd):
        text = struct.pack("!iiB", t, self.seq, cmd)
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
        print(t, seq)

    def handle_challenge(self, data, cmd, respond):
        # Increment sequence number
        self.increment()

        # Calculate the challenge
        t = int(float(time.time()))
        challenge = self.compute_challenge(t, cmd)

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
            self.handle_packet(data, lambda response: sock.sendto(response, addr))

if __name__ == "__main__":
    buzzer = Buzzer("soopersekret", ["guanrocks"])
    buzzer.listen("0.0.0.0", 4242)
