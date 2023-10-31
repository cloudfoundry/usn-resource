#!/usr/bin/env bash

set -ex

source ~/.bashrc

cd usn-resource

echo -e "\n Running tests..."
go run github.com/onsi/ginkgo/v2/ginkgo --keep-going --trace --race -vv -r $@
