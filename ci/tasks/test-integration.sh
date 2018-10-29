#!/usr/bin/env bash

set -ex

source ~/.bashrc

export GOPATH=$(pwd)/gopath
export GOBIN=$GOPATH/gobin
export PATH=/usr/local/go/bin:$GOPATH:$GOBIN:$PATH

cd gopath/src/github.com/cloudfoundry/usn-resource

echo -e "\n Cleaning..."
go clean -r .

echo -e "\n Installing ginkgo..."
go get -u github.com/onsi/ginkgo/ginkgo

echo -e "\n Installing gomega..."
go get -u github.com/onsi/gomega/...

echo -e "\n Running unit tests..."
ginkgo -r $race -keepGoing -trace $@
