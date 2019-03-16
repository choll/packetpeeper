#!/bin/sh -e

target_dir="third_party_repos"
#breakpad_branch="chrome_64"
breakpad_branch="chrome_58"
#hexfiend_tag="v2.4.0"
hexfiend_tag="v2.10b5"

mkdir -p ${target_dir}
cd ${target_dir}

test -d breakpad || git clone --depth 1 --branch ${breakpad_branch} --no-checkout https://github.com/google/breakpad.git
cd breakpad
git checkout ${breakpad_branch}
xcodebuild -project src/client/mac/Breakpad.xcodeproj -config Release
xcodebuild -project src/tools/mac/dump_syms/dump_syms.xcodeproj -config Release
cd ..
test -L ../Breakpad.framework || ln -s ${target_dir}/breakpad/src/client/mac/build/Release/Breakpad.framework ../Breakpad.framework

test -d HexFiend || git clone --depth 1 --branch ${hexfiend_tag} --no-checkout https://github.com/ridiculousfish/HexFiend.git
cd HexFiend
git checkout ${hexfiend_tag}
xcodebuild -target HexFiend_Framework -config Release
cd ..
test -L ../HexFiend.framework || ln -s ${target_dir}/HexFiend/build/Release/HexFiend.framework ../HexFiend.framework

