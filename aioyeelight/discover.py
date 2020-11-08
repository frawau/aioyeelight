import logging
import asyncio as aio
import socket
from struct import pack
from functools import partial

log = logging.getLogger(__name__)

# UPNP_PORT = 1982
UPNP_PORT = 54321
UPNP_ADDR = "239.255.255.250"
_DISCOVERYTIMEOUT = 360

try:
    from aiozeroconf import ServiceBrowser, Zeroconf

    async def do_close(zc):
        await zc.close()

    class YeelightListener(object):
        """
        Handling discovery
        """

        def __init__(self, newlight, gonelight=None):
            self.new_callb = newlight
            self.gone_callb = gonelight

        def remove_service(self, zeroconf, type_, name):
            if self.gone_callb:
                self.gone_callb(name)
            logging.debug(f"Service {name}: {type_} has gone away")

        def add_service(self, zeroconf, type_, name):
            aio.ensure_future(self.found_service(zeroconf, type_, name))

        async def found_service(self, zeroconf, type_, name):
            try:
                info = await zeroconf.get_service_info(type_, name)
                resu = {}
                if info.address:
                    resu["address"] = (socket.inet_ntoa(info.address), info.port)
                if info.address6:
                    resu["address6"] = (
                        socket.inet_ntop(netifaces.AF_INET6, info.address6),
                        info.port,
                    )
                if info.server:
                    resu["name"] = info.server
                if info.properties:
                    for key, value in info.properties.items():
                        if key.decode() == "mac":
                            resu["mac"] = ":".join(
                                [
                                    value[i : i + 2].decode()
                                    for i in range(0, len(value), 2)
                                ]
                            )
                if self.new_callb:
                    self.new_callb(resu)
                # logging.debug(f"Adding {info}")
            except Exception as e:
                logging.error(f"Problem with device found: {e}")

    def start_yeelight_discovery(handler, gone_handler=None, iface=None):
        loop = aio.get_event_loop()
        zeroconf = Zeroconf(loop, iface=iface)
        listener = YeelightListener(handler, gone_handler)
        browser = ServiceBrowser(zeroconf, "_miio._udp.local.", listener)
        return zeroconf, browser

    def test():
        logging.basicConfig(level=logging.DEBUG)
        broadcaster = {}

        def handler(sender):
            print("I GOT ONE")
            print(sender)

        loop = aio.get_event_loop()
        zc, browser = start_yeelight_discovery(handler)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            print("\n", "Exiting at user's request")
        finally:
            # Close the server
            browser.cancel()
            loop.run_until_complete(zc.close())
            loop.close()


except:

    def start_yeelight_discovery(handler):
        raise Exception("You need to install aiozeroconf")

    def test():
        print("You need aiozeroconf to test.")


if __name__ == "__main__":
    test()
