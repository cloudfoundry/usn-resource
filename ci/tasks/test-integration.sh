#!/usr/bin/env bash

set -ex

source ~/.bashrc

cd usn-resource

echo -e "\n Running unit tests..."
go run github.com/onsi/ginkgo/ginkgo -r $race -keepGoing -trace $@
