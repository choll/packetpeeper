# Packet Peeper

[![Xcode - Build](https://github.com/choll/packetpeeper/actions/workflows/objective-c-xcode.yml/badge.svg)](https://github.com/choll/packetpeeper/actions/workflows/objective-c-xcode.yml)

## Latest Release

Download [here](https://github.com/choll/packetpeeper/releases/download/2021-07-18/PacketPeeper_2021-07-18.dmg)

## Building

* git submodule update --init --recursive
* xcodebuild -target All -configuration Release

If you want to build a dmg file you can use:

* xcodebuild -target CreateDiskImage -configuration Release

## Releases

* Push a tag with pattern YYYY-MM-DD and a corresponding disk image will be uploaded to the GitHub release assets by Azure Pipelines.
