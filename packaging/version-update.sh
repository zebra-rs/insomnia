#! /bin/bash

# Propagate the top-level `version` file into Cargo.toml. cargo-deb reads the
# package version straight from Cargo.toml, so this is the single place the
# package version is set.
for file in ../Cargo.toml
do
    sed -i "s/^version = .*/version = \"$(cat ../version)\"/" ${file}
done
