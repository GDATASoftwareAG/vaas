# KDE Dolphin VaaS Integration

This repo contains an experimental prototype to integrate the G DATA VaaS API into KDE Dolphin.

It allows the user to right-click any file and click on *Scan with GDATA* to get a verdict for the file.

## Installation

Build the app **before you install** the plugin!

```bash
# Build the app
cargo build --release

# (Optional) Strip the executable to reduce the size
strip target/release/gdata_vaas_ui
```

Install the *Dolphin* plugin with the `install.sh` script.

## Uninstall

Uninstall the *Dolphin* plugin with the `uninstall.sh` script.


## Dev Information

KDE Dolphin Developer documentation: 
 - https://develop.kde.org/docs/dolphin/service-menus/ 
 - https://wiki.ubuntuusers.de/KDE-Servicemen%C3%BCs/
 - https://freeaptitude.altervista.org/articles/populate-the-kde-service-menu.html

SixtyFPS Documentation:
 - https://sixtyfps.io/
 - https://github.com/sixtyfpsui/sixtyfps/tree/master/examples