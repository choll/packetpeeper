# Packet Peeper
![Packet Peeper Logo](https://packetpeeper.github.io/ppicon.png)

[![Azure Pipelines][azure-badge]][azure-link]

[azure-badge]: https://dev.azure.com/cholloway/PacketPeeper/_apis/build/status/choll.packetpeeper?branchName=master
[azure-link]: https://dev.azure.com/cholloway/PacketPeeper/_build/latest?definitionId=2&branchName=master

## Building:

* git submodule update --init --recursive
* xcodebuild -target All -configuration Release

If you want to build a dmg file you can use:

* xcodebuild -target CreateDiskImage -configuration Release

## Releases:

* Push a tag with pattern YYYY-MM-DD and a corresponding disk image will be uploaded to the GitHub release assets by Azure Pipelines.
