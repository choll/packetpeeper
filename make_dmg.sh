#!/bin/sh
rm -rf build/Deployment
xcodebuild -target All -configuration Deployment
hdiutil create build/Deployment/PacketPeeper_$(date '+%Y-%m-%d').dmg -srcfolder 'build/Deployment/Packet Peeper.app'

