#!/usr/bin/env bash

fly -t production set-pipeline \
    -p usn-resource \
    -c pipeline.yml
