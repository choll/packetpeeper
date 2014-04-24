#!/bin/sh
rm -rf build/Deployment
DATE=$(date '+%Y-%m-%d')
sed s/BUNDLE_VERSION_PLACEHOLDER/$DATE/g PacketPeeper.plist.template > PacketPeeper.plist
xcodebuild -target All -configuration Deployment
hdiutil create build/Deployment/PacketPeeper_$DATE.dmg -volname "Packet Peeper" -srcfolder 'build/Deployment/Packet Peeper.app'

