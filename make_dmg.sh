#!/bin/sh
./fetch_and_build_dependencies.sh
DATE=$(date '+%Y-%m-%d')
sed -i '.make_dmg_backup'  s/BUNDLE_VERSION_PLACEHOLDER/$DATE/g PacketPeeper.plist
xcodebuild -target All -configuration Release
mv PacketPeeper.plist.make_dmg_backup PacketPeeper.plist
hdiutil create build/Release/PacketPeeper_$DATE.dmg -volname "Packet Peeper" -srcfolder 'build/Release/Packet Peeper.app'

