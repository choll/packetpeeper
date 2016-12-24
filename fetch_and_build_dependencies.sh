#!/bin/sh -e

target_dir=third_party_repos

if [ -d ${target_dir} ]; then
    echo "${target_dir} dir already exists"
    exit 1
fi

mkdir ${target_dir}
cd ${target_dir}

git clone https://github.com/google/breakpad.git
pushd breakpad
git checkout chrome_55
xcodebuild -project src/client/mac/Breakpad.xcodeproj -config Release
xcodebuild -project src/tools/mac/dump_syms/dump_syms.xcodeproj -config Release
popd
ln -s ${target_dir}/breakpad/src/client/mac/build/Release/Breakpad.framework Breakpad.framework

git clone https://github.com/ridiculousfish/HexFiend.git
pushd HexFiend
git checkout v2.4.0
xcodebuild -target HexFiend_Framework -config Release
popd
ln -s ${target_dir}/HexFiend/build/Release/HexFiend.framework HexFiend.framework

