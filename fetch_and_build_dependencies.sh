#!/bin/sh -e

target_dir="third_party_repos"
hexfiend_tag="v2.10.0"

mkdir -p ${target_dir}
cd ${target_dir}

test -d HexFiend || git clone --depth 1 --branch ${hexfiend_tag} --no-checkout https://github.com/ridiculousfish/HexFiend.git
cd HexFiend
git checkout ${hexfiend_tag}
xcodebuild -target HexFiend_Framework -config Release
cd ..
test -L ../HexFiend.framework || ln -s ${target_dir}/HexFiend/build/Release/HexFiend.framework ../HexFiend.framework

