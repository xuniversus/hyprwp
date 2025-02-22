I made this program to manage [Almamu's linux-wallpaperengine](https://github.com/Almamu/linux-wallpaperengine)
for my monitors in Hyprland. I have no prior C expertise/experience, but together with ChatGPT I cooked this up.
99%+ is AI generated and then proof read by project lead.
It' currently dependent on [Troydhanson's uthash.h](https://github.com/troydhanson/uthash).

No License from my side, except for those of the dependencies of the project.
Beyond uthash.h it should only be standard libraries. Only built for Linux.
It's built on Hyprland's IPC sockets, adding and removing wallpapers on monitor connection and disconnects.
It takes monitor names from ```hyprctl monitors``` as positional input arguments to bootstrap wallpapers at start.

Compile with ```gcc -Wall -O3 -march=native -o hyprwp hyprwp.c```

Run with ```hyprwp --config ~/.hyprwp "$(hyprctl monitors | fgrep Monitor | cut -d" " -f2 | tr "\n" " ")"```
Or use ```exec-once = hyprctl dispatch exec -- hyprwp --config ~/.hyprwp "$(hyprctl monitors | fgrep Monitor | cut -d" " -f2 | tr "\n" " ")"```
in your hyprland config.

For people on multiple GPU's and using iGPU primarily, prepend ```hyprwp``` with ```prime-run``` to run in NVIDIA GPU.


DISCLAIMER: Again, while the project is not licensed, any dependencies with licenses must be respected and followed.
If it wasn't obvious, only Linux and linux-wallpaperengine is officially supported,
but should be able to use any binary that takes
```hyprctl monitors```, ```monitoraddedv2```, and ```monitorremoved``` ```MONITORNAME``` as monitor input argument.

The config is very simple, the descriptions and arguments are seperated with whitespace, and if you need whitespace
in the argument use quotes/"" to enclose the full argument.
