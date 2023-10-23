#!/usr/bin/env bash

./cmd/radius-dict-gen/radius-dict-gen -package tgpp dictionaries/vendors/dictionary.3gpp >./vendors/tgpp/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package airespace dictionaries/vendors/dictionary.airespace >./vendors/airespace/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package ascend dictionaries/vendors/dictionary.ascend >./vendors/ascend/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package chakavak dictionaries/vendors/dictionary.chakavak >./vendors/chakavak/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package cisco dictionaries/vendors/dictionary.cisco >./vendors/cisco/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package fortinet dictionaries/vendors/dictionary.fortinet >./vendors/fortinet/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package huawei dictionaries/vendors/dictionary.huawei >./vendors/huawei/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package microsoft dictionaries/vendors/dictionary.microsoft >./vendors/microsoft/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package mikrotik dictionaries/vendors/dictionary.mikrotik >./vendors/mikrotik/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package quintum dictionaries/vendors/dictionary.quintum >./vendors/quintum/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package wispr dictionaries/vendors/dictionary.wispr >./vendors/wispr/generated.go
./cmd/radius-dict-gen/radius-dict-gen -package zte dictionaries/vendors/dictionary.zte >./vendors/zte/generated.go

#./cmd/radius-dict-gen/radius-dict-gen -package standard dictionaries/dictionary.standard >./standard/standard.go
#./cmd/radius-dict-gen/radius-dict-gen -ref "Service-Type:github.com/ParspooyeshFanavar/go-radius/standard" -package standard dictionaries/dictionary.sip >./standard/sip.go
