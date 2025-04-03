#!/usr/bin/env bash

script_dir="$( cd "$( dirname "$0" )" && pwd )"

fly -t "${CONCOURSE_TARGET:-bosh}" set-pipeline \
    -p usn-resource \
    -c ${script_dir}/pipeline.yml
