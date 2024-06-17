#!/usr/bin/env bash
set -ex

cd usn-resource

go run github.com/onsi/ginkgo/v2/ginkgo --keep-going --trace --race -vv -r $@
