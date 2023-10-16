package attributemap

import (
	"log"

	"github.com/ParspooyeshFanavar/go-radius"
	dict "github.com/ParspooyeshFanavar/go-radius/dictionary"
)

type (
	TypeMapperFunc func(byte) (string, dict.AttributeType, func(uint32) (string, error))
	NameMapperFunc func(string) (radius.Type, dict.AttributeType, func(string) (uint32, error))
	mappers        struct {
		typeMapper TypeMapperFunc
		nameMapper NameMapperFunc
	}
)

// vendorMappers is a map from vendorID to mapper functions
var vendorMappers map[uint32]mappers = make(map[uint32]mappers)

// RegisterVendor for register TypeMapper and NameMapper functions for vendor
func RegisterVendor(vendorID uint32, getAttrByOIDFunc TypeMapperFunc, getAttrByNameFunc NameMapperFunc) {
	if getAttrByOIDFunc == nil || getAttrByNameFunc == nil {
		log.Fatalf("dictionary for vendor id %d hasnt mapper funcs", vendorID)
	}
	vendorMappers[vendorID] = mappers{
		typeMapper: getAttrByOIDFunc,
		nameMapper: getAttrByNameFunc,
	}
}

// GetOIDMapper return TypeMapper function for a specific registered vendor
func GetOIDMapper(vendorID uint32) (typeMapper TypeMapperFunc, ok bool) {
	v, ok := vendorMappers[vendorID]
	if !ok {
		return nil, ok
	}
	typeMapper = v.typeMapper
	return
}

// GetNameMapper return NameMapper function for a specific registered vendor
func GetNameMapper(vendorID uint32) (typeMapper NameMapperFunc, ok bool) {
	v, ok := vendorMappers[vendorID]
	if !ok {
		return nil, ok
	}
	typeMapper = v.nameMapper
	return
}

// FindVSATypeByName find vendorID,oid,attributeType and value mapper function for a vendor specific attribute
func FindVSATypeByName(name string) (int, radius.Type, dict.AttributeType, func(string) (uint32, error)) {
	for vendorID, mappers := range vendorMappers {
		oid, aTyp, mapperFunc := mappers.nameMapper(name)
		if oid > 0 {
			return int(vendorID), oid, aTyp, mapperFunc
		}
	}

	return -1, -1, -1, nil
}
