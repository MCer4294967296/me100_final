# from board import LED
import math
from machine import Pin
from network import AP_IF, STA_IF, WLAN
import socket, time, ubinascii, ucryptolib
from umqtt.simple import MQTTClient

import uping


class DoorLock(object):
    def __init__(self, connect_retry=10):

        ap = WLAN(AP_IF)
        ap.active(1)
        sta = WLAN(STA_IF)
        sta.active(1)
        self.s = socket.socket()
        self.s.bind(("0.0.0.0", 80))
        self.s.listen(1)
        
        self.ssid, self.password = "", ""
        self.connect_retry = connect_retry
        self.lock_status = 0
        try:
            wificonfig = open("wificonfig", "r")
            self.ssid, self.password = config.read().split("\n")[:2]
            wificonfig.close()
        except Exception:
            pass

        if not self.ssid:
            print("config does not exist, initializing config")
            self.first_time_raw()
        else:
            print("found existing config, connecting to wifi")
            success = self.connect_to_wifi()

        self.s.settimeout(2)

        self.IV = bytes()
        self.key = bytes()
        with open("aes", "rb") as f:
            self.IV = f.read(16)
            self.key = f.read()
        self.IV = b'[S\x83\x11v\x9cY;\xbcH\xe3\t\xd6\xf9\xbf\x9f'
        self.key = b'b\xe7\x02$D\x18\x0c\xd8I5:\x1d%\xeft\xdb'
        self.cipher = ucryptolib.aes(key, 2, IV)

        self.last_sender_addr = "0.0.0.0"
        with open("lastsender", "r") as f:
            self.last_sender_addr = f.read()
        
        topic = "mcer4294967296/data"
        broker = "mqtt.eclipse.org"
        print("connecting to MQTT")
        mqtt = MQTTClient("umqtt_client", broker)
        mqtt.connect()
        print("connected to MQTT")
        mqtt.subscribe(topic)
        mqtt.set_callback(self.on_receive_mqtt)

        self.override = False
        self.at_home = False
        self.dist_thresh = 0.5 # kilometer
        self.timestamp_left = time.time()
        self.time_thresh = 60 # seconds
        self.poll_interval = 5 # seconds
        self.key_update_thresh = 86400 # a day
        self.last_key_update = time.time()

        self.lock_indicator = Pin(13, mode=Pin.OUT)

    def loop(self):
        while True:
            new_at_home = self.check_for_owner_on_wifi()
            if self.at_home and not new_at_home:
                # if, when we last checked, owner was at home
                # and now he is not, then we say he left the house
                self.timestamp_left = time.time()
                self.lock()
            if new_at_home and time.time() - self.timestamp_left > self.time_thresh:
                # if owner is now at home and it has been more than
                # 1 minutes since he left, we say he is coming home.
                self.unlock()
            self.at_home = new_at_home
            
            if time.time() - self.last_key_update > self.key_update_thresh and new_at_home:
                # if owner is on the network and we haven't updated AES key for a while,
                # begin to wait on socket for the phone to initiate one.
                self.poll_for_key_exchange()
            time.sleep(self.poll_interval)

    def poll_once_for_key_exchange(self):
        conn, addr = self.s.accept()
        if addr != self.last_sender_addr:
            print("got connection from unknown source when waiting for key: ", addr)
            print("abort.")
            return
        content = conn.recv(256)
        if not content.startswith(b"YOLO::key::"):
            return # it doesn't match our protocol

        try:
            blob = content.split(b"::")[2]
            self.IV, self.key = blob[:16], blob[16:]
            self.cipher = ucryptolib.aes(key, 2, IV)
        except:
            return

        with open("aes", "wb") as f:
            f.write(self.IV)
            f.write(self.key)
    
    def check_for_owner_on_wifi(self, timeout=2): # seconds
        tx, rx = uping.ping(last_sender_addr, count=1, timeout=timeout*1000)
        return rx == tx
    
    def on_receive_mqtt(self, topic, message):
        if topic != "mcer4294967296/data":
            return
        # stuff over mqtt will be encrypted
        try:
            encrypted = ubinascii.a2b_base64(message)
            decrypted = self.cipher.decrypt(encrypted)
        except:
            return

        print("received mqtt message, decrypted into: ", decrypted)
        if decrypted.startswith(b"YOLO::override"):
            order = decrypted.split(b"::")[2]
            if order == b"lock":
                self.lock()
            elif order == b"unlock":
                self.unlock()
            self.override = True
        elif decrypted.startswith(b"YOLO::unoverride"):
            self.override = False
        elif decrypted.startswith(b"YOLO::dist"):
            dist = decrypted.split(b"::")[2]
            try:
                dist = float(dist)
            except:
                print("float conversion failed")
                return
            if dist > self.dist_thresh:
                # if owner is pretty far away, we increase the poll interval
                # because it won't result in anything anyways.
                self.lock()
                self.poll_interval = 30
            else:
                # if owner is coming back home, we don't unlock the door because
                # maybe he wants to take a cigarette somewhere first.
                # but we decrease the interval so that we can detect more quickly.
                self.poll_interval = 5
        else:
            return

    def connect_to_wifi(self):
        print("connecting to wifi at " + self.ssid)
        sta = WLAN(STA_IF)
        if not sta.active():
            sta.active(1)
        sta.connect(self.ssid, self.password)

        count = 0
        while not sta.isconnected() and count < self.connect_retry:
            time.sleep(1)
            count += 1

        if not sta.isconnected():
            sta.active(0)
            print("failed to connect to wifi, deactivating STA interface")
        else:
            print("connected to wifi")
        return sta.isconnected()

    def first_time_raw(self):

        # wifi connection phase
        while True:
            conn, addr = self.s.accept()
            print("got connection, from", addr)
            content = conn.recv(256)
            if not content.startswith(b"YOLO::wifi::"):
                continue # it doesn't match our protocol
            ssid, password = content.split(b"::")[2:]
            self.ssid = str(ssid)
            self.password = str(password)
            success = self.connect_to_wifi()
            if success:
                conn.send(b"YOLO::connected::{}::{}".format(ssid, sta.ifconfig()[0]))
                conn.close()
                with open("wificonfig", "w") as f:
                    f.write(ssid+"\n"+password)
                break
            else:
                self.ssid, self.password = "", ""
                conn.send(b"YOLO::f")
                conn.close()
                continue
        
        # AES key receive phase
        while True:
            conn, addr = self.s.accept()
            print("got connection, from", addr)
            content = conn.recv(256)
            if not content.startswith(b"YOLO::key::"):
                continue # it doesn't match our protocol

            try:
                blob = content.split(b"::")[2]
                IV, key = blob[:16], blob[16:]
            except:
                continue

            with open("aes", "wb") as f:
                f.write(IV)
                f.write(key)

            break
            
        last_sender_addr = addr
        with open("lastsender", "w") as f:
            f.write(last_sender_addr)

        return key

    def lock():
        if self.override:
            return
        self.lock_status = 1
        self.lock_indicator(1)
        print("========door is locked========")

    def unlock():
        if self.override:
            return
        self.lock_status = 0
        self.lock_indicator(0)
        print("=======door is unlocked=======")


doorlock = DoorLock()
doorlock.loop()