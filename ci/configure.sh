#!/usr/bin/env bash

script_dir="$( cd "$( dirname "$0" )" && pwd )"

fly -t bosh-ecosystem set-pipeline \
    -p usn-resource \
    -c ${script_dir}/pipeline.yml
