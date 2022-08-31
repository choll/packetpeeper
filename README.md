# Packet Peeper

[![Xcode](https://github.com/choll/packetpeeper/actions/workflows/build.yml/badge.svg)](https://github.com/choll/packetpeeper/actions/workflows/build.yml)

## Latest Release

Download [here](https://github.com/choll/packetpeeper/releases/download/2022-08-31/PacketPeeper_2022-08-31.dmg)

## Building

* git submodule update --init --recursive
* xcodebuild -target All -configuration Release

If you want to build a dmg file you can use:

* xcodebuild -target CreateDiskImage -configuration Release

## Releases

* Push a tag with pattern YYYY-MM-DD and a release will be created containing a disk image built from the tag.
