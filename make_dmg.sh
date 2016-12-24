#!/bin/sh
rm -rf build/Release
DATE=$(date '+%Y-%m-%d')
sed s/BUNDLE_VERSION_PLACEHOLDER/$DATE/g PacketPeeper.plist.template > PacketPeeper.plist
xcodebuild -target All -configuration Release
hdiutil create build/Release/PacketPeeper_$DATE.dmg -volname "Packet Peeper" -srcfolder 'build/Release/Packet Peeper.app'

