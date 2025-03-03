I made this program to manage [Almamu's linux-wallpaperengine](https://github.com/Almamu/linux-wallpaperengine)
for my monitors in Hyprland. I have no prior C expertise/experience, but together with ChatGPT I cooked this up.
95%+ is AI generated and then proof read by project lead.

No License from my side, except for those of the dependencies of the project.
It should only be standard libraries. Only built for Linux.
It's built on Hyprland's IPC sockets, adding and removing wallpapers on monitor connection and disconnects.

Compile with ```gcc -Wall -O3 -march=native -o hyprwp hyprwp.c```

Run with ```hyprwp --config ~/.hyprwp```
Or use ```exec-once = hyprctl dispatch exec -- hyprwp --config ~/.hyprwp```
in your hyprland config.

For people on multiple GPU's and using iGPU primarily, prepend ```hyprwp``` with ```prime-run``` to run in NVIDIA GPU.

If it wasn't obvious, only Linux and linux-wallpaperengine is officially supported,
but should be able to use any binary that takes
```hyprctl monitors```, ```monitoraddedv2```, and ```monitorremoved``` ```MONITORNAME``` as monitor input argument.

The config is very simple, the descriptions and arguments are seperated with whitespace, and if you need whitespace
in the argument use quotes/"" to enclose the full argument.
