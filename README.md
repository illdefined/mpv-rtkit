## Synopsis

This is a proof‐of‐concept plugin for [mpv](https://mpv.io/) to enable real‐time scheduling on Linux through
[RealtimeKit](https://github.com/heftig/rtkit).

## Usage

Build the plugin using the included Nix flake or makefile.

The plugin may be installed to a suitable location like `~/.config/mpv/scripts` or loaded directly through the `--script` argument
to mpv.

### Build dependencies

- GNU make
- Clang or GCC
- mpv (`libmpv-dev`)
- D‐Bus (`libdbus-1-dev`)

## Intellectual property

This work is licenced under the [European Union Public Licence](https://spdx.org/licenses/EUPL-1.2.html).
