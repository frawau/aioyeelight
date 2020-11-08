#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This application is an example on how to use aiolifx
#
# Copyright (c) 2016 François Wautier
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
import sys
import os
import json
import asyncio as aio
import aioyeelight as aiox
from base64 import b64decode
from functools import partial
import argparse
import logging
from random import randint

UDP_BROADCAST_PORT = 56700


# Simple bulb control from console
class bulbs:
    """ A simple class with a register and  unregister methods
    """

    def __init__(self):
        self.bulbs = []
        self.pending_bulbs = []
        self.boi = None  # bulb of interest

    def register(self, bulb):
        global opts
        # print("Adding bulb {} {} {}".format(bulb,bulb.name,bulb.bulb_id))
        self.bulbs.append(bulb)
        self.bulbs.sort(key=lambda x: x.name or str(x.bulb_id))
        if opts.extra:
            bulb.register_callback(lambda y: print("Unexpected message: %s" % str(y)))
        try:
            self.pending_bulbs.remove(bulb)
        except:
            pass

    def unregister(self, bulb):
        idx = 0
        for x in list([y.bulb_id for y in self.bulbs]):
            if x == bulb.bulb_id:
                del self.bulbs[idx]
                break
            idx += 1

    def new_bulb(self, info):
        if "light" in info["name"] and info["mac"] in tokenlist:
            newbulb = aiox.YeelightBulb(
                aio.get_event_loop(),
                tokenlist[info["mac"]],
                info["address"],
                info["mac"],
                self,
            )
            found = False
            for abulb in self.bulbs:
                if abulb.bulb_id == newbulb.bulb_id:
                    found = True
                    break
            if not found:
                for abulb in self.pending_bulbs:
                    if abulb.bulb_id == newbulb.bulb_id:
                        found = True
                        break

            if not found:
                # print("Activating bulb {} with id {}".format(newbulb,newbulb.bulb_id))
                self.pending_bulbs.append(newbulb)
                newbulb.set_connections(2)  # Open 2 channels to the bulb
                newbulb.set_queue_limit(100, "adapt")
                newbulb.activate()
            else:
                del newbulb

    def close(self):
        for x in self.bulbs:
            x.cleanup()


async def flood_yeelight(light, count):
    for x in range(0, count):
        red = randint(0, 255)
        green = randint(0, 255)
        blue = randint(0, 255)
        light.set_rgb_direct(red, green, blue, light.brightness)
        await aio.sleep(0.2)


def start_music_result(cmd, data):
    if "error" in data:
        print("Music Mode could not {}".format(cmd))
    elif "result" in data and data["result"] == ["ok"]:
        print("Music Mode was {}{}ed".format(cmd, cmd == "stop" and "p" or ""))
    else:
        print("Don't know what this response to {} is: {}".format(cmd, data))


def prop_callb(boi, resu):
    for prop in boi.properties:
        print("\t{}:\t{}".format(prop.title(), boi.properties[prop]))
    print(f"\tNumber connections:\t{len(boi.transports)}")


def readin():
    """Reading from stdin and displaying menu"""
    global MyBulbs

    selection = sys.stdin.readline().strip("\n")
    MyBulbs.bulbs.sort(key=lambda x: x.name or str(x.bulb_id))
    lov = [x for x in selection.split(" ") if x != ""]
    if lov:
        if MyBulbs.boi:
            try:
                if int(lov[0]) == 0:
                    MyBulbs.boi = None
                elif int(lov[0]) == 1:
                    if len(lov) > 1 and lov[1].lower() in ["on", "off"]:
                        MyBulbs.boi.set_power(lov[1].lower())
                        MyBulbs.boi = None
                    else:
                        logging.error("Error: For power you must indicate on or off\n")
                elif int(lov[0]) == 2:
                    if len(lov) > 2:
                        try:
                            MyBulbs.boi.set_white_direct(
                                int(round(float(lov[2]))),
                                min(100, int(round(float(lov[1])))),
                            )

                            MyBulbs.boi = None
                        except:
                            logging.error(
                                "Error: For white brightness (0-100) and temperature (1700-6500) must be numbers.\n"
                            )
                    else:
                        logging.error(
                            "Error: For white you must indicate brightness (0-100) and temperature (1700-6500)\n"
                        )
                elif int(lov[0]) == 3:
                    if len(lov) > 3:
                        try:
                            MyBulbs.boi.set_hsv_direct(
                                min(359, int(round(float(lov[1])))),
                                int(round(float(lov[2]))),
                                int(round(float(lov[3]))),
                            )
                            MyBulbs.boi = None
                        except:
                            logging.error(
                                "Error: For colour Hue (0-359), Saturation (0-100) and Brightness (0-100)) must be numbers.\n"
                            )
                    else:
                        logging.error(
                            "Error: For colour you must indicate Hue (0-359), Saturation (0-100) and Brightess (0-100)\n"
                        )

                elif int(lov[0]) == 4:
                    if len(lov) > 4:
                        # try:
                        MyBulbs.boi.set_hsv(
                            min(359, int(round(float(lov[2])))),
                            int(round(float(lov[3]))),
                            "smooth",
                            int(round(float(lov[1]) * 1000)),
                        )
                        MyBulbs.boi.set_brightness(
                            min(100, int(round(float(lov[4])))),
                            "smooth",
                            int(round(float(lov[1]) * 1000)),
                        )
                        MyBulbs.boi = None
                        # except:
                        # logging.error("Error: For Smooth colour Duration, Hue (0-359), Saturation (0-100) and Brightness (0-100)) must be numbers.\n")
                    else:
                        logging.error(
                            "Error: For Smooth colour you must indicate Hue (0-359), Saturation (0-100) and Brightness (0-100)\n"
                        )
                elif int(lov[0]) == 5:
                    pbulb = MyBulbs.boi
                    MyBulbs.boi.get_prop(
                        [x for x in MyBulbs.boi.properties.keys()],
                        partial(prop_callb, MyBulbs.boi),
                    )
                    print(
                        "\tMessage Queue:\t{}".format(MyBulbs.boi.message_queue.qsize())
                    )
                    MyBulbs.boi = None
                elif int(lov[0]) == 6:
                    try:
                        MyBulbs.boi.set_name(" ".join(lov[1:]))
                        MyBulbs.boi = None
                    except:
                        logging.error("Error: Could not set name\n")
                elif int(lov[0]) == 7:
                    if len(lov) > 3:
                        # try:
                        myflow = aiox.Flow(50, aiox.EndState.Start)
                        myflow.add_rgb_transition(
                            1, lov[1], lov[2], lov[3], MyBulbs.boi.brightness
                        )
                        rgb = MyBulbs.boi.rgb
                        myflow.add_rgb_transition(
                            1,
                            rgb["red"],
                            rgb["green"],
                            rgb["blue"],
                            MyBulbs.boi.brightness,
                        )
                        MyBulbs.boi.start_flow(myflow)
                        MyBulbs.boi = None
                        # except:
                        # logging.error("Error: For pulse Red (0-255), Green (0-255) and Blue (0-255) must be numbers.\n")
                    else:
                        logging.error(
                            "Error: For pulse you must indicate Red (0-255), Green (0-255) and Blue (0-255)\n"
                        )
                elif int(lov[0]) == 8:
                    # try:
                    count = int(lov[1])
                    aio.ensure_future(flood_yeelight(MyBulbs.boi, count))
                    MyBulbs.boi = None
                    # except:
                    # logging.error("Error: For Stress you must specify a count (Integer)\n")
                elif int(lov[0]) == 9:
                    cmd = str(lov[1]).lower()
                    if cmd not in ["start", "stop"]:
                        logging.error(
                            'Error: For "music mode" you must indicate "start" or "stop"\n'
                        )
                    else:
                        MyBulbs.boi.set_music(cmd, 0, partial(start_music_result, cmd))
                        MyBulbs.boi = None

            except Exception as e:
                logging.error("\nError: Selection must be a number.\n")
                logging.debug(f"Ooops : {e}")
                logging.exception(e)
        else:
            try:
                logging.debug("Mo BOI")
                if int(lov[0]) > 0:
                    if int(lov[0]) <= len(MyBulbs.bulbs):
                        MyBulbs.boi = MyBulbs.bulbs[int(lov[0]) - 1]
                    else:
                        logging.error("\nError: Not a valid selection.\n")

            except:
                logging.error("\nError: Selection must be a number.\n")

    if MyBulbs.boi:
        print("Select Function for {}:".format(MyBulbs.boi.name))
        print("\t[1]\tPower (on or off)")
        print("\t[2]\tWhite (Brigthness Temperature)")
        print("\t[3]\tColour (Hue Saturation Brightness)")
        print("\t[4]\tSlow Colour Change (Duration Hue Saturation Brightness)")
        print("\t[5]\tInfo")
        print("\t[6]\tSet Name (Bulb name)")
        print("\t[7]\tPulse (Red Green Blue)")
        print("\t[8]\tStress (Number of colour changes)")
        print("\t[9]\tStart/Stop Music mode (start or stop)")
        print("")
        print("\t[0]\tBack to bulb selection")
    else:
        idx = 1
        print("Select Bulb:")
        for x in MyBulbs.bulbs:
            print("\t[{}]\t{}".format(idx, x.name or x.bulb_id))
            idx += 1
    print("")
    print("Your choice: ", end="", flush=True)


def main(args=None):
    global MyBulbs
    global opts
    global tokenlist

    parser = argparse.ArgumentParser(
        description="Track and interact with Yeelight light bulbs."
    )
    parser.add_argument(
        "-x",
        "--extra",
        action="store_true",
        default=False,
        help="Print unexpected messages.",
    )
    parser.add_argument(
        "-D",
        "--database",
        default="~/.aioyeelight",
        help="JSON file used to keep device mac/key matching.",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", default=False, help="Print debug info"
    )
    try:
        opts = parser.parse_args()
    except Exception as e:
        parser.error("Error: " + str(e))

    try:
        opts.database = os.path.abspath(os.path.expanduser(opts.database))
        with open(opts.database, "r") as tokendata:
            tokenlist = json.load(tokendata)
        for mac in tokenlist:
            tokenlist[mac] = b64decode(tokenlist[mac])
    except:
        logging.critical(f"I can't seem to be able to load keys from {opts.database}")
        sys.exit(1)

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)

    MyBulbs = bulbs()
    loop = aio.get_event_loop()
    zc, browser = aiox.start_yeelight_discovery(MyBulbs.new_bulb)
    try:
        loop.add_reader(sys.stdin, readin)
        print('Hit "Enter" to start')
        print("Use Ctrl-C to quit")
        loop.run_forever()
    except:
        pass
    finally:
        print("Exiting at user's request.")
        browser.cancel()
        loop.run_until_complete(zc.close())
        MyBulbs.close()
        loop.remove_reader(sys.stdin)
        loop.run_until_complete(aio.sleep(3))
        loop.close()


if __name__ == "__main__":
    MyBulbs = None
    opts = None
    tokenlist = {}
    main()
