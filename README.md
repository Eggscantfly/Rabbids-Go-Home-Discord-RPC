# RGH-Discord-RPC
Discord Rich Presence DLL for Rabbids Go Home PC Port.

## Features
* Shows current level name on Discord
* Displays stuff collected count in real-time
* Shows elapsed playtime

## Requirements
* Discord RPC SDK (discord-rpc)
* Visual Studio 2022
* Windows PC

## Building
1. Download discord-rpc from https://github.com/discord/discord-rpc/releases
2. Put the `include` and `lib` folders in `RGH_Discord/discord-rpc/`
3. Build as Release x86

## Installation
Option 1: Rename the compiled DLL to `DBGHELP.dll` and put it in the game's root directory.

Option 2: Use the RGH RPC Setup for a patched exe that loads `RGH_RPC.dll` directly.

