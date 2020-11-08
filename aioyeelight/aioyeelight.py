#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This library is an asyncio library to communicate with Yeelight Yeelight
# LED lights.
#
# Copyright (c) 2017 François Wautier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE

import asyncio as aio
import json
from functools import partial
from enum import IntEnum
from uuid import uuid4
import datetime as dt
from random import randint
import socket
import logging
import hashlib
from base64 import b64encode, b64decode
from struct import pack, unpack
from typing import Any, List, Mapping, Union, Callable, Optional

# https://cryptography.io/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from time import time

_backend = default_backend()


def md5(inp: bytes) -> bytes:
    m = hashlib.md5()
    m.update(inp)
    return m.digest()


def key_iv(token: bytes) -> (bytes, bytes):
    """Derive (Key, IV) from a Xiaomi MiHome device token (128 bits)."""
    key = md5(token)
    iv = md5(key + token)
    return (key, iv)


def AES_cbc_encrypt(token: bytes, plaintext: bytes) -> bytes:
    """Encrypt plain text with device token."""
    key, iv = key_iv(token)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext)
    padded_plaintext += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def AES_cbc_decrypt(token: bytes, ciphertext: bytes) -> bytes:
    """Decrypt cipher text with device token."""
    key, iv = key_iv(token)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(bytes(ciphertext)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_plaintext = unpadder.update(padded_plaintext)
    unpadded_plaintext += unpadder.finalize()
    return unpadded_plaintext


def encrypt(stamp: int, token: bytes, devid: int, plaindata: bytes) -> bytes:
    """Generate an encrypted packet from plain data.

    Args:
        stamp: incrementing counter
        token: 128 bit device token
        plaindata: plain data
    """

    def init_msg_head(stamp: int, token: bytes, devid: int, packet_len: int) -> bytes:
        # print(f"len {packet_len.__class__}")
        # print(f"devid {devid.__class__}")
        # print(f"stamp {stamp.__class__}")
        head = pack(
            "!BBHIII16s",
            0x21,
            0x31,  # const magic value
            packet_len,
            0,  # unknown const
            devid,  # unknown const
            # 0x02AF3988,  # unknown const
            stamp,
            token,  # overwritten by the MD5 checksum later
        )
        return head

    payload = AES_cbc_encrypt(token, plaindata)
    packet_len = len(payload) + 32
    packet = bytearray(init_msg_head(stamp, token, devid, packet_len) + payload)
    checksum = md5(packet)
    for i in range(0, 16):
        packet[i + 16] = checksum[i]
    return packet


def decrypt(token: bytes, cipherpacket: bytes) -> bytes:
    """Decrypt a packet.

    Args:
        token: 128 bit device token
        cipherpacket: packet data
    """
    ciphertext = cipherpacket[32:]
    plaindata = AES_cbc_decrypt(token, ciphertext)
    return plaindata


# Yeelight properties/commands

PROPERTIES = [
    "power",
    "bg_power",
    "bright",
    "bg_bright",
    "nl_br",
    "ct",
    "bg_ct",
    "rgb",
    "bg_rgb",
    "hue",
    "bg_hue",
    "sat",
    "bg_sat",
    "color_mode",
    "bg_lmode",
    "flowing",
    "bg_flowing",
    "flow_params",
    "bg_flow_params",
    "music_on",
    "name",
    "delayoff",
    "fw_ver",
    "model",
    "id",
]

PROPERTIES_COMMANDS = {
    "power": ["set_power", "toggle"],
    "bg_power": ["bg_set_power", "bg_toggle", "dev_toggle"],
    "bright": ["set_bright", "adjust_bright", "set_scene"],
    "bg_bright": ["bg_set_bright", "bg_set_scene"],
    "nl_br": [],
    "ct": ["set_ct_abx", "ajust_ct", "set_scene"],
    "bg_ct": ["bg_set_ct_abx", "bg_ajust_ct", "bg_set_scene"],
    "rgb": ["set_rgb", "adjust_color", "set_scene"],
    "bg_rgb": ["bg_set_rgb", "bg_adjust_color", "bg_set_scene"],
    "hue": ["set_hsv", "adjust_color", "set_scene"],
    "bg_hue": ["bg_set_hsv", "bg_adjust_color", "bg_set_scene"],
    "sat": ["set_hsv", "adjust_color", "set_scene"],
    "bg_sat": ["bg_set_hsv", "bg_adjust_color", "bg_set_scene"],
    "color_mode": [],
    "bg_lmode": [],
    "flowing": ["start_cf", "stop_cf"],
    "bg_flowing": ["bg_start_cf", "bg_stop_cf"],
    "flow_params": [],
    "bg_flow_params": [],
    "music_on": ["set_music"],
    "name": [],
    "delayoff": [],
    "fw_ver": [],
    "model": [],
    "id": [],
}

INT_PROPERTIES = [
    "bright",
    "bg_bright",
    "nl_br",
    "ct",
    "bg_ct",
    "rgb",
    "bg_rgb",
    "hue",
    "bg_hue",
    "sat",
    "bg_sat",
    "delayoff",
    "color_mode",
]
HEX_PROPERTIES = ["id"]

DEFAULT_TIMEOUT = 1.0  # How long to wait for a response
DEFAULT_ATTEMPTS = 3  # How many times to try
MESSAGE_WINDOW = 256


class Mode(IntEnum):
    Default = 0
    RGB = 1
    White = 2
    HSV = 3
    Flow = 4
    Night = 5
    Sleep = 7


class EndState(IntEnum):
    Start = 0
    Stop = 1
    Off = 2


class FlowMode(IntEnum):
    Colour = 1
    White = 2
    Pause = 7


class Flow:
    """
    This class describes a flow, a transition sequence used to create complex effects
    """

    def __init__(self, count, end):
        """
        This class describes a sequence of transitions.

        :param count: The number of transitions. 0 means repeat at perpetuum
        :type count: int
        :param end: The end state, one of start, end or off
        :type end: EndState
        """
        self.count = count
        self.end = end
        self.flow_val = []

    def add_rgb_transition(self, duration, red, green, blue, brightness):
        """
        Add a RGB transitiion to the flow
        """
        trans = [int(round(duration * 1000)), FlowMode.Colour.value]
        rgb = int(round(float(red) * 65535.0 + float(green) * 256 + float(blue)))
        trans.append(rgb)
        trans.append(int(round(brightness)))
        self.flow_val += trans

    def add_hsv_transition(self, duration, hue, saturation, brightness):
        """
        Add a HSV transitiion to the flow
        """

        def hsv_to_rgb(hue, sat, val):
            """
            Adapted from https://stackoverflow.com/questions/24852345/hsv-to-rgb-color-conversion
            """
            h = hue / 360
            s = sat / 100
            v = val / 100
            if s == 0.0:
                v *= 255
                return (v, v, v)
            i = int(h * 6.0)  # XXX assume int() truncates!
            f = (h * 6.0) - i
            p, q, t = (
                int(255 * (v * (1.0 - s))),
                int(255 * (v * (1.0 - s * f))),
                int(255 * (v * (1.0 - s * (1.0 - f)))),
            )
            v = int(v * 255)
            i %= 6
            if i == 0:
                return (v, t, p)
            if i == 1:
                return (q, v, p)
            if i == 2:
                return (p, v, t)
            if i == 3:
                return (p, q, v)
            if i == 4:
                return (t, p, v)
            if i == 5:
                return (v, p, q)

        trans = [int(round(duration * 1000)), FlowMode.Colour.value]
        red, green, blue = hsv_to_rgb(hue, saturation, brighness)
        rgb = int(round(float(red) * 65535.0 + float(green) * 256 + float(blue)))
        trans.append(rgb)
        trans.append(int(round(brightness)))
        self.flow_val += trans

    def add_white_transition(self, duration, temp, brightness):
        """
        Add a RGB transitiion to the flow
        """
        trans = [int(round(duration * 1000)), FlowMode.White.value]
        trans.append(int(round(temp)))
        trans.append(int(round(brightness)))
        self.flow_val += trans

    def add_pause_transition(self, duration):
        """
        Add a RGB transitiion to the flow
        """
        trans = [int(round(duration * 1000)), FlowMode.Pause.value]
        trans.append(0)
        trans.append(0)
        self.flow_val += trans

    @property
    def flow(self):
        return ",".join([str(x) for x in self.flow_val])


class MiioPacket:
    def __init__(self):
        self.magic = (0x21, 0x31)
        self.length = None
        self.unknown1 = 0
        self.devid = 0
        self.stamp = 0
        self.data = None
        self.md5 = None

    def read(self, raw: bytes):
        """Parse the payload of a UDP packet."""
        head = raw[:32]
        self.magic, self.length, self.unknown1, self.devid, self.stamp, self.md5 = unpack(
            "!2sHIII16s", head
        )
        self.data = raw[32:]

    def generate(self, token: bytes) -> bytes:
        """Generate an encrypted packet."""
        return encrypt(self.stamp, token, self.devid, self.data)


class YeelightConnection(aio.DatagramProtocol):
    """
    This is the base class for any connection to a Yeelight. It deals with theirencryption bits and so one
    """

    def __init__(self, parent: Any, token: bytes) -> aio.Protocol:
        self.parent = parent
        self.token = token
        self.device_id = 0
        self.transport = None
        self.last_sent = dt.datetime.now()
        self.decrypt = False
        self.stamp = int(time()) % 10000
        self.ping_to = 21
        self.ping_stop = False
        self.ping_task = self.parent.loop.create_task(self._ping())

    def send_hello(self):
        payload = b"\x21\x31\x00\x20" + b"\xff" * 28
        self.transport.sendto(payload)

    #
    # Protocol Methods
    #

    def connection_made(self, transport):
        """Method run when the connection to the lamp is established
        """
        self.transport = transport
        self.parent.register(self)
        self.send_hello()

    def connection_lost(self, error):
        logging.debug("Connection Lost")
        if self.parent:
            self.parent.unregister(self)

    def datagram_received(self, data, addr):
        try:
            mydata = MiioPacket()
            mydata.read(data)
            if not self.decrypt:
                # logging.debug(f"When in init got {data}")
                if data[:4] == b"\x21\x31\x00\x20":
                    self.addr = addr[0]
                    self.device_id = mydata.devid
                    self.stamp = mydata.stamp
                    self.decrypt = True
                    self.parent.initialize()
                else:
                    logging.debug("Not what we expected. I am stymied.")
            else:
                plaindata = json.loads(decrypt(self.token, data))
                logging.debug(f"We got {plaindata}")
                self.parent.data_received(plaindata)
        except Exception as e:
            if data[:4] == b"\x21\x31\x00\x20":
                # logging.debug("Got ping response")
                self.addr = addr[0]
                self.device_id = mydata.devid
                self.stamp = mydata.stamp
                self.decrypt = True
            else:
                logging.debug(f"Ooops while receiving: {e}")

    def write(self, msg):
        logging.debug(f"Sending {msg} with token {self.token}")
        try:
            self.last_sent = dt.datetime.now()
            packet = MiioPacket()
            packet.stamp = self.stamp
            packet.data = msg.encode()
            packet.devid = self.device_id
            realpayload = packet.generate(self.token)
            # print(f"Sending {packet.data} for {packet.devid}")
            # print(["0x%02x" % x for x in realpayload])
            self.transport.sendto(realpayload)
        except Exception as e:
            logging.debug(f"Ooops ... could not send: {e}")

    def close(self):
        logging.debug("Explicit close")
        self.ping_stop = True
        self.transport.close()

    async def _ping(self):
        while not self.ping_stop:
            tnow = dt.datetime.now()
            if tnow - dt.timedelta(seconds=self.ping_to) > self.last_sent:
                # logging.debug("Pinging")
                self.last_sent = tnow
                self.send_hello()
            await aio.sleep(3)


class YeelightMusicConnect(aio.Protocol):
    """This class is a single server connection to a Xiaomi device

        :param parent: The parent object. Must have register, unregister and data_received methods
        :type parent: object
        :param future: A future object, set when connection is made
        :type future: aio.Future
        :param autoclose: Indicate how long (in secs) to idle before cancelling the music mode. If 0
                          the music mode must be explicitly stopped.
        :type autoclose: float
    """

    def __init__(self, parent, future, autoclose=0):
        self.parent = parent
        self.future = future
        self.autoclose = autoclose
        self.transport = None
        self.last_sent = dt.datetime.now()
        # print("Music Mode Server Created")

    #
    # Protocol Methods
    #

    def connection_made(self, transport):
        """Method run when the connection to the lamp is established
        """

        # print("Got connection from {}".format(transport.get_extra_info('peername')))
        logging.debug(f"Connected to Yeelight via {transport}")
        self.transport = transport
        self.future.set_result(self)
        if self.autoclose:
            xx = self.parent.loop.create_task(self._autoclose_me())

    def connection_lost(self, error):
        self.parent.music_mode_off()

    def data_received(self, data):
        # self.parent.data_received(data)
        # print("MUSIC Received {}".format(data)) #Are we supposed to receive something?
        pass

    def write(self, msg):
        logging.debug("Music Sending {}".format(msg))
        self.last_sent = dt.datetime.now()
        self.transport.write((msg + "\r\n").encode())

    def close(self):
        self.transport.close()

    async def _autoclose_me(self):
        while True:
            if dt.datetime.now() - self.last_sent > dt.timedelta(
                seconds=self.autoclose
            ):
                # print("Time to cleanup")
                self.close()
                return
            await aio.sleep(1)


class YeelightBulb(object):
    """This correspond to a single light bulb.

    This handles all the communications with a single bulb. This is created upon
    discovery of the bulb.


        :param loop: The async loop being used
        :type loop: asyncio.EventLoop
        :param address: A 2-uple ip address, port
        :type headers: list
        :param mac: A sting, mac address
        :type headers: str
        :param parent: Parent object with register/unregister methods
        :type parent: object
        :param tnb: The number of connections to establish with the bulb (default 1)
        :type tnb: int

     """

    def __init__(self, loop, token, address, mac, parent=None, tnb=1):
        self.loop = loop
        self.parent = parent
        self.mac = mac
        self.token = token
        self.support = []
        self.properties = {}
        self.ip_address = address[0]
        self.port = address[1]
        self.seq = 0
        # Key is the message sequence, value is a callable
        self.pending_reply = {}
        self.tnb = max(1, min(4, tnb))  # Minimum 1, max 4 per Yeelight specs
        self.transports = []
        self.tidx = 0
        self.musicm = False
        self.timeout_secs = DEFAULT_TIMEOUT
        self.default_attempts = DEFAULT_ATTEMPTS
        self.registered = False
        self.message_queue = aio.Queue()
        self.queue_limit = 0  # No limit
        self.queue_policy = "drop"  # What to do when limit is reached
        self.is_sending = False
        self.my_ip_addr = ""
        self.initialized = False

    def activate(self):
        # Start the transports
        logging.debug(f"Activating {self.tnb} transports")
        for x in range(self.tnb):
            listen = self.loop.create_datagram_endpoint(
                partial(YeelightConnection, self, self.token),
                remote_addr=(self.ip_address, self.port),
            )
            xx = aio.ensure_future(listen)

    def seq_next(self):
        """Method to return the next sequence value to use in messages.

            :returns: next number in sequensce (modulo 128)
            :rtype: int
        """
        self.seq = (self.seq + 1) % MESSAGE_WINDOW
        return self.seq

    async def try_sending(self, timeout_secs=None, max_attempts=None):
        """Coroutine used to send message to the device when a response is needed.

        This coroutine will try to send up to max_attempts time the message, waiting timeout_secs
        for an answer. If no answer is received, it will consider that the device is no longer
        accessible and will unregister it.

            :param timeout_secs: Number of seconds to wait for a response
            :type timeout_secs: int
            :param max_attempts: .
            :type max_attempts: int
            :returns: a coroutine to be scheduled
            :rtype: coroutine
        """
        logging.debug("Trying to send")
        try:
            if timeout_secs is None:
                timeout_secs = self.timeout_secs
            if max_attempts is None:
                max_attempts = self.default_attempts  # So we can detect failure quickly
            mydelta = dt.timedelta(seconds=1)
            dodelay = len(self.transports) - 1
            while not self.message_queue.empty():
                callb, msg = await self.message_queue.get()
                logging.debug(f"Sender: From queue got {msg}, musicm is {self.musicm}")
                self.message_queue.task_done()
                if self.musicm:
                    if isinstance(self.musicm, aio.Future):
                        # print("Awaiting Future {}".format(self.musicm))
                        try:
                            x = await aio.wait_for(self.musicm, timeout=2)
                            self.musicm = self.musicm.result()
                        except:
                            # Oops
                            self.musicm = False
                            # print("Future Failed")
                            # self.message_queue.trim(self.queue_limit)
                            continue  # We just drop the extra messages
                        # print("Future gave {}".format(self.musicm))
                    self.musicm.write(json.dumps(msg))
                    if callb:
                        callb({"id": msg["id"], "result": ["ok"]})
                else:
                    attempts = 0
                    while attempts < max_attempts:
                        now = dt.datetime.now()
                        cid = msg["id"]
                        event = aio.Event()
                        self.pending_reply[cid] = [event, callb]
                        attempts += 1
                        myidx = self.tidx
                        self.tidx = (self.tidx + 1) % len(self.transports)
                        diff = now - self.transports[myidx].last_sent
                        if diff < mydelta:
                            await aio.sleep((mydelta - diff).total_seconds())
                        self.transports[myidx].write(json.dumps(msg))
                        try:
                            myresult = await aio.wait_for(event.wait(), timeout_secs)
                            self.tidx = (self.tidx + 1) % len(self.transports)
                            break
                        except Exception as inst:
                            if attempts >= max_attempts:
                                if cid in self.pending_reply:
                                    callb = self.pending_reply[cid][1]
                                    if callb:
                                        callb(None)
                                    del self.pending_reply[cid]
                                # It's dead Jim
                                self.unregister(self.transports[myidx])
                                if len(self.transports) == 0:
                                    self.is_sending = False
                                    return
                            else:
                                print("Trying to recover")
                                self.transports[myidx].send_hello()
                    if dodelay:
                        dodelay -= 1
                        await aio.sleep(1.0 / len(self.transports))
        except Exception as e:
            logging.debug(f"Exception while sending: {e}")

        self.is_sending = False

    def send_msg_noqueue(self, msg, callb=None):
        """Sending a message by-passing the queue
        """
        cid = self.seq_next()
        msg["id"] = cid
        if callb:
            self.pending_reply[cid] = [None, callb]
        self.transports[0].write(json.dumps(msg))

    def send_msg(self, msg, callb=None, timeout_secs=None, max_attempts=None):
        """ Let's send
        """
        logging.debug("Sending {}".format(msg))
        if self.queue_limit == 0 or self.message_queue.qsize() < self.queue_limit:
            cid = self.seq_next()
            msg["id"] = cid
            self.message_queue.put_nowait((callb, msg))
            logging.debug(f"Put {callb}, {msg} on queue")
            if not self.is_sending:
                self.is_sending = True
                xxx = self.loop.create_task(
                    self.try_sending(timeout_secs, max_attempts)
                )
        elif self.queue_limit > 0:
            logging.debug("Dropping message")
            pass  # Just drop

    def data_received(self, data):
        # Do something
        try:
            # print("Received raw data: {}".format(data))
            received_data = data
            if "id" in received_data:
                cid = int(received_data["id"])
                if cid in self.pending_reply:
                    myevent, callb = self.pending_reply[cid]
                    if myevent:
                        myevent.set()
                    if callb:
                        callb(received_data)
                    del self.pending_reply[cid]

        except Exception as e:
            logging.debug(f"Oops Oops  Problem {e}")
            logging.exception(e)

    #
    # Yeelight method
    #

    def get_prop(self, props, callb=None):
        """Get current values of light properties

            :param props:  list of properties
            :type props: list
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: True if supported, False if not
            :rtype: bool
        """
        if "get_prop" in self.support:
            self.send_msg(
                {"method": "get_prop", "params": props},
                partial(self._get_prop_reply, props, callb),
            )
            return True
        return False

    def _get_prop_reply(self, request, callb, result):
        """Get current values of light properties

        :param props:  list of properties
        :type props: list
        """
        # print("\n\nYeelight For {} got {}\n\n".format(request,result))
        if result and "result" in result:

            if self.support == [] and len(PROPERTIES) == len(result["result"]):
                self.support = [
                    "get_prop",
                    "cron_add",
                    "cron_get",
                    "cront_del",
                    "set_default",
                    "set_name",
                ]
                for key, val in zip(PROPERTIES, result["result"]):
                    if not val:
                        continue
                    self.support.extend(PROPERTIES_COMMANDS[key])
                    if key in INT_PROPERTIES:
                        self.properties[key] = int(val)
                    elif key in HEX_PROPERTIES:
                        self.properties[key] = int(val, base=16)
                    else:
                        self.properties[key] = val
                self.support = list(set(self.support))
            elif "music_on" not in self.properties or self.properties["music_on"] != 1:
                for prop, val in zip(request, result["result"]):
                    if prop in PROPERTIES:
                        if prop in INT_PROPERTIES:
                            self.properties[prop] = int(val)
                        elif prop in HEX_PROPERTIES:
                            self.properties[prop] = int(val, base=16)
                        else:
                            self.properties[prop] = val
                if callb:
                    callb(result)

    def _cmd_reply(self, props, callb, result):
        """Generic command result.

            :param props: A dictionary of properties affected by the command with
                          their value
            :type props: dict
            :param reply" Result of command "ok" or not
            :param callb: Callback
            :type callb: callable
            :returns: None
            :rtype: None
        """
        try:
            if result:
                # logging.debug(
                # f"Generic callback with {result} and {props} for {self.properties}"
                # )
                if "result" in result and result["result"] == ["ok"]:
                    for p, v in props.items():
                        self.properties[p] = v

            if callb:
                callb(result)
        except Exception as e:
            logging.error(f"Exception in call back: {e}")

    def set_temperature(self, temp, effect="sudden", duration=100, callb=None):
        """Set temperature of light

            :param temp:  Temperature in K (1700 - 6500 K)
            :type temp: int
            :param effect: One of "smooth" or "suddent"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "set_ct_abx" in self.support:

            thiscallb = partial(self._cmd_reply, {"ct": temp}, callb)
            if effect == "smooth":
                duration = max(30, duration)  # Min is 30 msecs
            self.send_msg(
                {"method": "set_ct_abx", "params": [temp, effect, duration]}, thiscallb
            )
            return True
        return False

    def set_rgb(self, red, green, blue, effect="sudden", duration=100, callb=None):

        """Set colour of light

            :param red:  red as int
            :type red: int
            :param green:  green as int
            :type green: int
            :param blue:  blue as int
            :type blue: int
            :param effect: One of "smooth" or "suddent"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if (0 <= red <= 255) and (0 <= green <= 255) and (0 <= blue <= 255):
            if self.properties["power"] == "on" and "set_rgb" in self.support:

                rgb = int(
                    round(float(red) * 65535.0 + float(green) * 256 + float(blue))
                )
                thiscallb = partial(self._cmd_reply, {"rgb": rgb}, callb)
                cid = self.seq_next()
                if effect == "smooth":
                    duration = max(30, duration)  # Min is 30 msecs
                self.send_msg(
                    {"method": "set_rgb", "params": [rgb, effect, duration]}, callb
                )
                return True
        else:
            logging.erro(
                f"Colour must be between 0 and 255, got red {red}, green {green}, and blue {blue}"
            )
        return False

    def set_hsv(self, hue, sat, effect="sudden", duration=100, callb=None):

        """Set colour of light

            :param hue:  hue as int (0-359)
            :type hue: int
            :param sat:  saturation as int (0-sat)
            :type sat: int
            :param effect: One of "smooth" or "suddent"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "set_hsv" in self.support:
            thiscallb = partial(self._cmd_reply, {"hue": hue, "sat": sat}, callb)
            if effect == "smooth":
                duration = max(30, duration)  # Min is 30 msecs
            self.send_msg(
                {"method": "set_hsv", "params": [hue, sat, effect, duration]}, thiscallb
            )
            return True
        return False

    def set_brightness(self, brightness, effect="sudden", duration=100, callb=None):

        """Set brightness of light

            :param brightness:  brightness as int (0-100)
            :type brightness: int
            :param effect: One of "smooth" or "suddent"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "set_bright" in self.support:
            thiscallb = partial(self._cmd_reply, {"btight": brightness}, callb)
            if effect == "smooth":
                duration = max(30, duration)  # Min is 30 msecs
                self.send_msg(
                    {"method": "set_bright", "params": [brightness, effect, duration]},
                    thiscallb,
                )
            return True
        return False

    def set_power(self, power, effect="sudden", duration=100, mode=None, callb=None):

        """Set power of light

            :param power:  Power mode ("on" or "off")
            :type power: str
            :param effect: One of "smooth" or "sudden"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param mode: Mode (from class Mode) to switch to
            :type mode: Mode
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "set_power" in self.support:
            thiscallb = partial(self._cmd_reply, {"power": power}, callb)
            if effect == "smooth":
                duration = max(30, duration)  # Min is 30 msecs
            if mode:
                self.send_msg(
                    {"method": "set_power", "params": [power, effect, duration, mode]},
                    thiscallb,
                )
            else:
                self.send_msg(
                    {"method": "set_power", "params": [power, effect, duration]},
                    thiscallb,
                )
            return True
        return False

    def set_default(self, callb=None):

        """Save current state as default

            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "set_default" in self.support:
            self.send_msg({"method": "set_default", "params": []}, callb)
            return True
        return False

    def bg_set_temperature(self, temp, effect="sudden", duration=100, callb=None):
        """Set temperature of light

            :param temp:  Temperature in K (1700 - 6500 K)
            :type temp: int
            :param effect: One of "smooth" or "suddent"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "bg_set_ct_abx" in self.support:
            thiscallb = partial(self._cmd_reply, {"bg_ct": temp}, callb)
            if effect == "smooth":
                duration = max(30, duration)  # Min is 30 msecs
            self.send_msg(
                {"method": "bg_set_ct_abx", "params": [temp, effect, duration]},
                thiscallb,
            )
            return True
        return False

    def bg_set_rgb(self, red, green, blue, effect="sudden", duration=100, callb=None):

        """Set colour of light

            :param red:  red as int
            :type red: int
            :param green:  green as int
            :type green: int
            :param bluee:  blue as int
            :type blue: int
            :param effect: One of "smooth" or "suddent"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if (0 <= red <= 255) and (0 <= green <= 255) and (0 <= blue <= 255):
            if self.properties["power"] == "on" and "bg_set_rgb" in self.support:

                rgb = int(
                    round(float(red) * 65535.0 + float(green) * 256 + float(blue))
                )
                thiscallb = partial(self._cmd_reply, {"bg_rgb": rgb}, callb)
                if effect == "smooth":
                    duration = max(30, duration)  # Min is 30 msecs
                self.send_msg(
                    {"method": "bg_set_rgb", "params": [rgb, effect, duration]},
                    thiscallb,
                )
                return True
        else:
            logging.erro(
                f"Colour must be between 0 and 255, got red {red}, green {green}, and blue {blue}"
            )
        return False

    def bg_set_hsv(self, hue, sat, effect="sudden", duration=100, callb=None):

        """Set colour of light

            :param hue:  hue as int (0-359)
            :type hue: int
            :param sat:  saturation as int (0-sat)
            :type sat: int
            :param effect: One of "smooth" or "suddent"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "bg_set_hsv" in self.support:
            thiscallb = partial(self._cmd_reply, {"bg_hue": hue, "bg_sat": sat}, callb)
            if effect == "smooth":
                duration = max(30, duration)  # Min is 30 msecs
            self.send_msg(
                {"method": "bg_set_hsv", "params": [hue, sat, effect, duration]},
                thiscallb,
            )
            return True
        return False

    def bg_set_brightness(self, brightness, effect="sudden", duration=100, callb=None):

        """Set brightness of light

            :param brightness:  brightness as int (0-100)
            :type brightness: int
            :param effect: One of "smooth" or "suddent"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["bg_power"] == "on" and "bg_set_bright" in self.support:
            thiscallb = partial(self._cmd_reply, {"bg_btight": brightness}, callb)
            if effect == "smooth":
                duration = max(30, duration)  # Min is 30 msecs
                self.send_msg(
                    {
                        "method": "bg_set_bright",
                        "params": [brightness, effect, duration],
                    },
                    thiscallb,
                )
            return True
        return False

    def bg_set_power(self, power, effect="sudden", duration=100, mode=None, callb=None):

        """Set power of light

            :param power:  Power mode ("on" or "off")
            :type power: str
            :param effect: One of "smooth" or "sudden"
            :type effect: str
            :param duration: "smooth" effect duration in millisecs
            :type duration: int
            :param mode: Mode (from class Mode) to switch to
            :type mode: Mode
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "bg_set_power" in self.support:
            thiscallb = partial(self._cmd_reply, {"bg_power": power}, callb)
            if effect == "smooth":
                duration = max(30, duration)  # Min is 30 msecs
            if mode:
                self.send_msg(
                    {
                        "method": "bg_set_power",
                        "params": [power, effect, duration, mode],
                    },
                    thiscallb,
                )
            else:
                self.send_msg(
                    {"method": "bg_set_power", "params": [power, effect, duration]},
                    thiscallb,
                )
            return True
        return False

    def toggle(self, callb=None):

        """Toggle power of light

            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "toggle" in self.support:
            thiscallb = partial(
                self._cmd_reply,
                {"power": "off" if self.properties["power"] == "on" else "on"},
                callb,
            )
            self.send_msg({"method": "toggle", "params": []}, callb)
            return True
        return False

    def bg_toggle(self, callb=None):

        """Toggle power of bg light

            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "bg_toggle" in self.support:
            thiscallb = partial(
                self._cmd_reply,
                {"bg_power": "off" if self.properties["bg_power"] == "on" else "on"},
                callb,
            )
            self.send_msg({"method": "bg_toggle", "params": []}, callb)
            return True
        return False

    def dev_toggle(self, callb=None):

        """Toggle power of light and bg light

            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "dev_toggle" in self.support:
            updparam = {
                "bg_power": "off" if self.properties["bg_power"] == "on" else "on"
            }
            updparam["power"] = "off" if self.properties["power"] == "on" else "on"
            thiscallb = partial(self._cmd_reply, updparam, callb)
            self.send_msg({"method": "dev_toggle", "params": []}, callb)
            return True
        return False

    def start_flow(self, flex, callb=None):

        """Set colour flow of light

            :param count: How many times is the flex to be ran. 0 means forever.
            :type count: integers
            :param endstate: What should be the state of the light at the end:
                                "start" same state as it was at the start of the flow
                                "stop" stay in the end state
                                "off" Light should be off at the end
            :param flex:  A transition object
            :type flex: Flow
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "start_cf" in self.support:
            self.send_msg(
                {
                    "method": "start_cf",
                    "params": [flex.count, flex.end.value, flex.flow],
                },
                callb,
            )
            return True
        return False

    def stop_flow(self, callb=None):

        """Stop a flow running on the light

            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "stop_cf" in self.support:
            self.send_msg({"method": "stop_cf", "params": []}, callb)
            return True
        return False

    def set_rgb_direct(self, red, green, blue, brightness, callb=None):

        """Set colour of light

            :param red:  red as int
            :type red: int
            :param green:  green as int
            :type green: int
            :param blue:  blue as int
            :type blue: int
            :param brightness: The brightness
            :type brightness: int
            :returns: None
            :rtype: None
        """
        if (0 <= red <= 255) and (0 <= green <= 255) and (0 <= blue <= 255):

            if "set_scene" in self.support:
                rgb = int(
                    round(float(red) * 65535.0 + float(green) * 256 + float(blue))
                )
                thiscallb = partial(
                    self._cmd_reply, {"rgb": rgb, "bright": brightness}, callb
                )
                self.send_msg(
                    {"method": "set_scene", "params": ["color", rgb, brightness]},
                    thiscallb,
                )
                return True
        return False

    def set_hsv_direct(self, hue, sat, brightness, callb=None):

        """Set colour of light

            :param hue:  hue as int (0-359)
            :type hue: int
            :param sat:  saturation as int (0-sat)
            :type sat: int
            :param brightness: The brightness
            :type brightness: int
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "set_scene" in self.support:
            thiscallb = partial(
                self._cmd_reply, {"hue": hue, "sat": sat, "bright": brightness}, callb
            )
            self.send_msg(
                {"method": "set_scene", "params": ["hsv", hue, sat, brightness]},
                thiscallb,
            )
            return True
        return False

    def set_white_direct(self, temperature, brightness, callb=None):

        """Set temperature and brightness of light

            :param temperature:  Lamp colour temperature
            :type temperature: int
            :param brightness: The brightness
            :type brightness: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "set_scene" in self.support:
            thiscallb = partial(
                self._cmd_reply, {"ct": temperature, "bright": brightness}, callb
            )
            self.send_msg(
                {"method": "set_scene", "params": ["ct", temperature, brightness]},
                thiscallb,
            )
            return True
        return False

    def set_flow_direct(self, count, endstate, flex, callb=None):
        """Set colour flow of light

            :param count: How many times is the flex to be ran. 0 means forever.
            :type count: integers
            :param endstate: What should be the state of the light at the end:
                                "start" same state as it was at the start of the flow
                                "stop" stay in the end state
                                "off" Light should be off at the end
            :param flex:  A list of transitions describing the flow expression. The list contains a
                          multiple of 4 of integers. Each set of 4 represents one effect. The 4 numbers are:
                                duration in msec
                                mode Mode.RGB.value, Mode.White.value or Mode.Sleep.value
                                value  the value  rgb or temperature
                                brightness: the brightness

            :type brightness: list
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """

        if "set_scene" in self.support:
            self.send_msg(
                {
                    "method": "set_scene",
                    "params": [
                        "cf",
                        count,
                        ["start", "stop", "off"].index(endstate.lower()),
                        flex,
                    ],
                },
                callb,
            )
            return True
        return False

    def set_timed_power(self, brightness, delay, callb=None):

        """Set temperature and brightness of light

            :param temperature:  Lamp colour temperature
            :type temperature: int
            :param brightness: The brightness
            :type brightness: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "set_scene" in self.support:
            self.send_msg(
                {
                    "method": "set_scene",
                    "params": ["auto_delay_off", brightness, delay],
                },
                callb,
            )
            return True
        return False

    def cron_add(self, action, delay, callb=None):

        """Set an action with a delay

            :param action:  Currently only "off"
            :type action: str
            :param delay: delay in minutes
            :type delay: int
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "cron_add" in self.support:
            self.send_msg(
                {
                    "method": "cron_add",
                    "params": [["off", "on"].index(action.lower()), delay],
                },
                callb,
            )
            return True
        return False

    def cron_del(self, action, callb=None):

        """Cancel a timed action

            :param action:  Currently only "off"
            :type action: str
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "cron_del" in self.support:
            self.send_msg(
                {"method": "cron_del", "params": [["off", "on"].index(action.lower())]},
                callb,
            )
            return True
        return False

    def cron_get(self, action, callb=None):

        """Cancel a timed action

            :param action:  Currently only "off"
            :type action: str
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if self.properties["power"] == "on" and "cron_get" in self.support:
            self.send_msg(
                {"method": "cron_get", "params": [["off", "on"].index(action.lower())]},
                callb,
            )
            return True
        return False

    # TODO implement these
    # def set_adjust 2 string(action) string(prop)

    def set_music(self, action, delay=5.0, callb=None):

        """Start music mode.

        Before starting the music mode, one must setup a server
        waiting at host:port

            :param action: start or stop
            :type action: str
            :param delay: Idle delay before closing
            :type delay: float
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "set_music" in self.support:

            if action.lower() == "start" and not self.musicm:
                thiscallb = partial(self._cmd_reply, {"music_on": 1}, callb)
                while True:
                    try:
                        myport = randint(9000, 24376)
                        sock = socket.socket()
                        sock.bind(
                            (self.my_ip_addr, myport)
                        )  # Make sure the port is free
                        break
                    except:
                        pass
                self.musicm = aio.Future()
                # print("Start Future {}".format(self.musicm))
                coro = self.loop.create_server(
                    partial(YeelightMusicConnect, self, self.musicm, delay), sock=sock
                )
                xx = aio.ensure_future(coro)
                # self.loop.call_soon(self.set_music,"start",self.my_ip_addr,myport)
                self.loop.call_soon(
                    self.send_msg_noqueue,
                    {
                        "method": "set_music",
                        "params": [
                            ["stop", "start"].index(action.lower()),
                            self.my_ip_addr,
                            myport,
                        ],
                    },
                    thiscallb,
                )
            elif action.lower() == "stop" and self.musicm:
                thiscallb = partial(self._cmd_reply, {"music_on": 0}, callb)
                self.loop.call_soon(
                    self.send_msg_noqueue,
                    {
                        "method": "set_music",
                        "params": [["stop", "start"].index(action.lower())],
                    },
                    thiscallb,
                )
                self.music_mode_off()
            else:
                return False
            return True
        return False

    def set_name(self, name, callb=None):

        """Set light name

            :param name:  New name
            :type name: str
            :param callb: a callback function. Given the list of values as parameters
            :type callb: callable
            :returns: None
            :rtype: None
        """
        if "set_name" in self.support:
            thiscallb = partial(self._cmd_reply, {"name": name}, callb)
            self.send_msg({"method": "set_name", "params": [name]}, thiscallb)
            return True
        return False

    #
    # Management Methods
    def register(self, conn):
        """A connection is registering
            return True
        return False
        """
        self.transports.append(conn)
        logging.debug("Registering connection {} for {}".format(conn, self.bulb_id))
        if not self.registered:
            self.my_ip_addr = conn.transport.get_extra_info("sockname")[0]
            self.registered = True
            if self.parent:
                self.parent.register(self)

    def unregister(self, conn):
        """Proxy method to unregister the device with the parent.
        """
        # print("Unregistering connection {} for {}".format(conn,self.bulb_id))
        for x in range(len(self.transports)):
            if self.transports[x] == conn:
                try:
                    self.transports[x].close()
                except:
                    pass

                del self.transports[x]
                break

        if len(self.transports) == 0 and self.registered:
            self.registered = False
            if self.parent:
                self.parent.unregister(self)

    def cleanup(self):
        """Method to call to cleanly terminate the connection to the device.
        """
        for x in self.transports:
            x.close()

    def set_connections(self, nb):
        """Function to set the number of connection to open to a single bulb.

        By default, Yeelight limits to 1 command per second per channel. You can
        increase that by opening more channels. In any case, the overall limit is 144
        commands per seconds, so more than 2 will create issues. This MUST be used before
        the bulb is activated. After that it has no effect.

        :param nb: The number of channels to open 1 to 4
        :type nb: int
        """
        self.tnb = nb

    def set_queue_limit(self, length, policy="drop"):
        """Set the queue size limit and the policy, what to do when the size limit is reached

            :param length: The maximum length of the message sending queue. 0 means no limit
            :type length: int
            :param policy: What to do when the queue size limit is reached. Values can be:
                    drop: drop the extra messages
                    head: drop the head of the queu
                    random: drop a random message in the queue
                    adapt: switch to "music" mode and send
        """
        self.queue_limit = length
        if policy != "adapt" or "set_music" in self.support:
            # Silently ignoring unsupported policy
            self.queue_policy = policy

    def music_mode_off(self):
        if self.musicm:
            # self.musicm is set to YeelightMusicConnect in try_sending. So if we stop without sending, we need to check.
            if isinstance(self.musicm, aio.Future):
                if not self.musicm.cancel():
                    try:
                        self.musicm.result().close()
                    except:
                        pass
            else:
                self.musicm.close()
            self.musicm = False

    def initialize(self):
        """
        Make sure we get the list of supported properties
        """
        if not self.initialized:
            self.initialized = True
            self.send_msg(
                {"method": "get_prop", "params": PROPERTIES},
                partial(self._get_prop_reply, PROPERTIES, None),
            )
            return True

    # A couple of proxies
    @property
    def power(self):
        if "power" in self.properties:
            return self.properties["power"]
        else:
            return "off"

    @property
    def colour(self):
        result = {"hue": 0, "saturation": 0, "brightness": 0}
        if "sat" in self.properties:
            result["saturation"] = self.properties["sat"]
        if "hue" in self.properties:
            result["hue"] = self.properties["hue"]
        if "bright" in self.properties:
            result["brightness"] = self.properties["bright"]

        return result

    @property
    def rgb(self):
        result = {"red": 0, "green": 0, "blue": 0}
        if "rgb" in self.properties:
            val = int(self.properties["rgb"])
            for col in ["blue", "green", "red"]:
                result[col] = val % 256
                val = int((val - result[col]) / 256)

            return result
        else:
            return result

    @property
    def brightness(self):
        if "bright" in self.properties:
            return int(self.properties["bright"])
        else:
            return 0

    @property
    def white(self):
        result = {"brightness": 0, "temperature": 0}
        if "ct" in self.properties:
            result["temperature"] = self.properties["ct"]
        if "bright" in self.properties:
            result["brightness"] = self.properties["bright"]

        return result

    @property
    def current_colour(self):
        if self.properties["color_mode"] == Mode.RGB.value:
            return self.rgb
        elif self.properties["color_mode"] == Mode.HSV.value:
            return self.colour
        else:
            return self.white

    @property
    def name(self):
        if "name" in self.properties:
            return self.properties["name"]
        else:
            return None

    @property
    def bulb_id(self):
        return self.mac
        # if "id" in self.properties:
        # return self.properties["id"]
        # else:
        # return None
