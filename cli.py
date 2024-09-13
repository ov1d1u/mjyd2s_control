import asyncio
import argparse
import logging
from bleak import BleakClient, BleakScanner

from mjyd2s import MJYD2S

DISCOVERY_TIMEOUT = 30.0

LOGGER = logging.getLogger(__name__)

async def discover(mac_address) -> BleakClient | None:
    while True:
        devices = await BleakScanner.discover()
        
        for device in devices:
            if device.address == mac_address:
                return device


async def run(args):
    ble_client = await asyncio.wait_for(
        discover(args.mac_address),
        timeout=DISCOVERY_TIMEOUT
    )
    
    if ble_client is None:
        LOGGER.error("Device not found")
        return
    
    mjyd2s = MJYD2S(ble_client, args.mi_token)
    await mjyd2s.connect()
    
    if args.action == 'turn_on':
        await mjyd2s.turn_on()
    elif args.action == 'turn_off':
        await mjyd2s.turn_off()
    elif args.action == 'set_brightness':
        await mjyd2s.set_brightness(args.brightness)
    elif args.action == 'set_duration':
        await mjyd2s.set_duration(args.duration)
    elif args.action == 'set_ambient':
        await mjyd2s.set_ambient()

def range_type(min_val, max_val, step=1):
    def range_check(value):
        value = int(value)
        if value < min_val or value > max_val or (value - min_val) % step != 0:
            raise argparse.ArgumentTypeError(f"Value must be between {min_val} and {max_val} and in steps of {step}")
        return value
    return range_check


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect to and control a Xiaomi Motion Activated Night Light 2.")
    parser.add_argument("--mac_address", required=True, help="Bluetooth MAC address (or device identifier on MacOS)")
    parser.add_argument("--mi_token", required=True, help="Xiaomi Mi Token")
    parser.add_argument("--action", required=True, choices=['turn_on', 'turn_off', 'set_brightness', 'set_duration', 'set_ambient'], help="Action control")
    parser.add_argument("extra_args", nargs=argparse.REMAINDER, help="Additional arguments for the action")
    
    parser.add_argument("--debug", action='store_true', help="Enable debug logging")
    args = parser.parse_args()
    
    mac = args.mac_address
    mi_token = args.mi_token
    
    if args.action in ['set_brightness', 'set_duration', 'set_ambient']:
        if not args.extra_args or len(args.extra_args) != 1:
            parser.error(f"{args.action} requires an additional argument")

        if args.action == 'set_brightness':
            try:
                args.brightness = range_type(1, 100)(args.extra_args[0])
            except argparse.ArgumentTypeError as e:
                parser.error(str(e))

        elif args.action == 'set_duration':
            try:
                args.timeout = range_type(15, 60)(args.extra_args[0])
            except argparse.ArgumentTypeError as e:
                parser.error(str(e))

        elif args.action == 'set_ambient':
            try:
                args.ambient = range_type(0, 100, 25)(args.extra_args[0])
            except argparse.ArgumentTypeError as e:
                parser.error(str(e))
    
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    
    asyncio.run(run(args))