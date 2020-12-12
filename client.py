# this is a stub because I did not have time to learn android programming
import base64, socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import paho.mqtt.client as paho
session = "mcer4294967296"
topic = "mcer4294967296/data"
BROKER = "mqtt.eclipse.org"
mqtt = paho.Client()
mqtt.connect(BROKER)

def key_exchange(remote):
    key = get_random_bytes(16)
    IV = get_random_bytes(16)
    key = b'b\xe7\x02$D\x18\x0c\xd8I5:\x1d%\xeft\xdb'
    IV = b'[S\x83\x11v\x9cY;\xbcH\xe3\t\xd6\xf9\xbf\x9f'
    s = socket.socket()
    s.connect((remote, 80))
    s.send(bytes("YOLO::key::", "utf-8") + IV + key)
    s.close()
    return IV, key

def pad_encrypt_b64(msg, cipher):
    padded += bytes([0] * (16 - (len(msg) % 16)))
    encrypted = cipher.encrypt(padded)
    b64 = base64.b64encode(encrypted)
    return b64

def main():
    remote = "192.168.4.1"
    key = bytes()
    try:
        f = open("phoneconfig", "r")
        remote = f.readline().strip()
        f.close()
    except:
        pass

    try:
        f = open("keyconfig", "rb")
        key = f.read()
        f.close()
    except:
        pass

    print(f"remote is at {remote}")
    
    while True:
        instruction = input()
        if instruction == "initialize":
            s = socket.socket()

            # wifi information transfer
            s.connect((remote, 80))
            s.send(b"YOLO::wifi::yvWR-2.4G:yvbbrjdr")
            recv = s.recv(32)
            s.close()
            if not recv.startswith("YOLO::connected"):
                print("board didn't reply with valid response")
                continue
            if recv.split("::")[1] == "f":
                print("board failed to connect")
                continue

            remote = recv.split("::")[-1]
            with open("phoneconfig", "w") as f:
                f.write(remote+"\n")
            
            # key exchange
            key, IV = key_exchange(remote)
            cipher = AES.new(key, AES.MODE_CBC, iv=IV)
        elif instruction == "key_exchange":
            key, IV = key_exchange(remote)
            cipher = AES.new(key, AES.MODE_CBC, iv=IV)
        elif instruction == "unoverride":
            payload = b"YOLO::unoverride::"
            mqtt.publish(topic, pad_encrypt_b64(payload, cipher))
        elif instruction.startswith("override"):
            choice = instruction[9:]
            if choice == "lock":
                payload = b"YOLO::override::lock::"
            elif choice == "unlock":
                payload = b"YOLO::override::unlock::"
            mqtt.publish(topic, pad_encrypt_b64(payload, cipher))
        elif instruction.startswith("mqtt"):
            distance = instruction[5:]
            payload = b"YOLO::dist::" + bytes(distance, "utf-8") + "::"
            mqtt.publish(topic, pad_encrypt_b64(payload, cipher))


if __name__ == "__main__":
    main()