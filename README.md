# Xiaomi Motion Activated Night Light 2 Controller

This Python script allows you to control a **Xiaomi Motion Activated Night Light 2** over Bluetooth using various actions such as turning the light on or off, adjusting brightness, setting duration, and modifying ambient light levels. It utilizes the provided Xiaomi Mi Token and the MAC address of the device to communicate and perform these actions.

## Features

- **Turn On / Turn Off** the night light.
- **Set Brightness** level (from 1 to 100).
- **Set Duration** for how long the light stays on (between 15 and 60 seconds).
- **Set Ambient Light Sensitivity** (values: 0, 25, 50, 75, 100).
- Debug mode for detailed logging output.

## Requirements

- Python 3.7+
- Bluetooth connectivity
- A Xiaomi Mi Token (see https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor for how to get one)
- The MAC address (or device identifier for macOS) of the Xiaomi Motion Activated Night Light 2 (can also be found using the script above)

## Usage

```bash
python mjyd2s.py --mac_address <MAC_ADDRESS> --mi_token <MI_TOKEN> --action <ACTION> [--debug] [EXTRA_ARGS]
```

### Parameters

- `--mac_address` (required): The Bluetooth MAC address (or device identifier on macOS) of the Xiaomi night light.
- `--mi_token` (required): The Xiaomi Mi Token used for authentication.
- `--action` (required): The action you want to perform on the device. Options:
  - `turn_on` — Turns on the light.
  - `turn_off` — Turns off the light.
  - `set_brightness` — Sets the brightness level (requires an additional argument between 1 and 100).
  - `set_duration` — Sets the duration for how long the light stays on (requires an additional argument between 15 and 60 seconds).
  - `set_ambient` — Adjusts ambient light sensitivity (requires an additional argument of 0, 25, 50, 75, or 100).

- `EXTRA_ARGS`: Used when the action requires additional input (brightness level, duration, or ambient light sensitivity).
- `--debug`: Enables detailed logging for troubleshooting.

### Examples

1. **Turn on the light:**
   ```bash
   python mjyd2s.py --mac_address AA:BB:CC:DD:EE:FF --mi_token abc123 --action turn_on
   ```

2. **Set brightness to 80:**
   ```bash
   python mjyd2s.py --mac_address AA:BB:CC:DD:EE:FF --mi_token abc123 --action set_brightness 80
   ```

3. **Set duration to 30 seconds:**
   ```bash
   python mjyd2s.py --mac_address AA:BB:CC:DD:EE:FF --mi_token abc123 --action set_duration 30
   ```

4. **Enable debug logging:**
   ```bash
   python mjyd2s.py --mac_address AA:BB:CC:DD:EE:FF --mi_token abc123 --action turn_off --debug
   ```

## Debug Mode

To enable more detailed logging and help troubleshoot any issues, pass the `--debug` flag to the script. This will display additional output including the steps being taken and any potential errors.

## Additional Information

- Ensure Bluetooth is enabled and functional on the device running the script.
- For actions requiring additional parameters (`set_brightness`, `set_duration`, `set_ambient`), only a single value should be provided.
- Warning: bugs ahead. Consider this an alpha version. I'm preparing a Home Assistant integration too.

## Resources

This script wouldn't be possible without help from some other projects on the internet:
- Yeelight xiaomi mesh light bulb auth sequence dump (@kabbi): https://gist.github.com/kabbi/32658d7d3a086cd47d877882933a9908
- TelinkMiFlasher (@pvvx): https://github.com/pvvx/pvvx.github.io/
- This blog post from Wankko Ree's Blog: https://wkr.moe/study/845.html

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for more details.

## Disclaimer

This script is provided as-is and is not an official Xiaomi product. Use at your own risk. Ensure you are authorized to control the target device.