# aioxiaomi

aioxiaomi is a Python 3/asyncio library to control Xiaomi Yeelight LED lightbulbs over your LAN.

[![PyPI version fury.io](https://badge.fury.io/py/aioyeelight.svg)](https://pypi.python.org/pypi/aioiotprov)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-licen)
[![GITHUB-BADGE](https://github.com/frawau/aioyeelight/workflows/black/badge.svg)](https://github.com/psf/black)

# Installation

We are on PyPi so

     pip3 install aioxiaomi
or
     python3 -m pip install aioyeelight


# Encryption Key

THis library uses the MIHome binary protocol as described by [OpenMiHome](https://github.com/OpenMiHome/mihome-binary-protocol)
This means you must acquire the envryption key that is generated during provisioning.

The easiest way is to provision the bulbs with [aioiotprov](https://github.com/frawau/aioiotprov).

# How to use

Essentially, you create an object with at least 2 methods:

    - register
    - unregister

You then use start_yeelight_discovery, to search for light bulbs with a callback that will create and .activate() any new bulb.
Upon connection with the bulb, it will register itself with the parent. All the method communicating with the bulb
can be passed a callback function to react to the bulb response. The callback should take 1 parameters:

    - the response message

Checkout __main__.py to see how it works.


In essence, the test program is this

    tokenlist = { <mac>: <secret token>}
    class bulbs():
    """ A simple class with a register and  unregister methods
    """
        def __init__(self):
            self.bulbs=[]
            self.pending_bulbs = []

        def register(self,bulb):
            self.bulbs.append(bulb)
            try:
                self.pending_bulbs.remove(bulb)
            except:
                pass

        def unregister(self,bulb):
            idx=0
            for x in list([ y.bulb_id for y in self.bulbs]):
                if x == bulb.bulb_id:
                    del(self.bulbs[idx])
                    break
                idx+=1

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
            for x in self.bulbs:
                if x.bulb_id == newbulb.bulb_id:
                    found = True
                    break
            if not found:
                for x in self.pending_bulbs:
                    if x.bulb_id == newbulb.bulb_id:
                        found = True
                        break
            if not found:
                newbulb.activate()
            else:
                del(newbulb)


    def readin():
    """Reading from stdin and displaying menu"""

        selection = sys.stdin.readline().strip("\n")
        DoSomething()

    MyBulbs= bulbs()
    loop = aio.get_event_loop()
    zc, browser = aiox.start_yeelight_discovery(MyBulbs.new_bulb)
    try:
        loop.add_reader(sys.stdin,readin)
        loop.run_forever()
    except:
        pass
    finally:
        browser.cancel()
        loop.run_until_complete(zc.close())
        MyBulbs.close()
        loop.remove_reader(sys.stdin)
        loop.close()


Other things worth noting:

- Discovery is done using [aiozeroconf](https://github.com/frawau/aiozeroconf)

- Yeelights allows only about 1 command per second per connection. To counter that,one can start more than one connection to a bulb. There is a limit of 4 connections per bulb, but given that there can only be 144 command per minute per bulb, only 2 connections can be handled without starting to overload the bulb. Use .set_connection(x) before activate to set the number of connections

- aioyeelight ensure that there is at most 1 command per second per connection. To do so it keeps a buffer of messages and pace the sending (using round-robin if there is more then one connection). The buffer can thus become quite big.

- aioyeelight will ping a bulb with a 'hello' message. This appears to be necessary for the bulb to keep responding.

- I only have "Color" model, so I could not test with other types of bulbs
