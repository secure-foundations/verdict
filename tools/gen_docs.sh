#!/bin/sh

cargo doc --no-deps \
    -p verdict \
    -p verdict-parser \
    -p verdict-polyfill \
    -p verdict-rspec-lib \
    -p vest
