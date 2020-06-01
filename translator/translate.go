package translator

import (
	"bitbucket.parspooyesh.com/ibscgw/radius"
	"bitbucket.parspooyesh.com/ibscgw/radius/attributemap"
	dict "bitbucket.parspooyesh.com/ibscgw/radius/dictionary"
	"bitbucket.parspooyesh.com/ibscgw/radius/rfc2865"
	"bitbucket.parspooyesh.com/ibscgw/radius/sip"
	"bitbucket.parspooyesh.com/ibscgw/radius/standard"
	"fmt"

	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/airespace"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/ascend"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/chakavak"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/cisco"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/fortinet"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/huawei"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/microsoft"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/mikrotik"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/quintum"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/tgpp"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/wispr"
	_ "bitbucket.parspooyesh.com/ibscgw/radius/vendors/zte"
)

// TranslateAttributes to translate radius attributes to a *map[string][]string
func TranslateAttributes(attributes *radius.Attributes) *map[string][]string {
	if attributes == nil || len(*attributes) < 1 {
		return nil
	}
	avp := make(map[string][]string, len(*attributes))

	for key, attr := range *attributes {
		if key == rfc2865.VendorSpecific_Type {
			for i := range attr {
				vendorID, vsa, err := radius.VendorSpecific(attr[i])
				if err != nil {
					continue
				}
				for len(vsa) >= 3 {
					vsaTyp, vsaLen := vsa[0], vsa[1]
					if int(vsaLen) > len(vsa) || vsaLen < 3 {
						break
					}

					name, typ, mapperFunc, _ := getVSANameType(vendorID, vsaTyp)

					value := decodeAttributeValue(vsa[2:int(vsaLen)], typ, mapperFunc)
					avp[name] = append(avp[name], value)

					vsa = vsa[int(vsaLen):]
				}

			}
		} else {
			for i := range attr {
				name, typ, mapperFunc := standard.GetAttrName(byte(key))
				if name == "" {
					name, typ, mapperFunc = sip.GetAttrName(byte(key))
				}
				if name == "" {
					continue
				}
				value := decodeAttributeValue(attr[i], typ, mapperFunc)
				avp[name] = append(avp[name], value)
			}
		}
	}
	return &avp
}

// TranslateMapToAttributes to translate a *map[string][]string to radius attributes
func TranslateMapToAttributes(attrMap *map[string][]string) *radius.Attributes {
	if attrMap == nil || len(*attrMap) < 1 {
		return nil
	}
	attrs := make(radius.Attributes)

	for typ, val := range *attrMap {
		for i := range val {
			attrType, attr, err := CreateAttribute(typ, val[i])
			if err != nil {
				continue
			}
			attrs.Add(attrType, attr)
		}
	}

	return &attrs
}

// getVSANameType return name, type and value mapper function for a specific vendorID and oid
func getVSANameType(vendorID uint32, vsaTyp byte) (name string, typ dict.AttributeType, mapperFunc func(uint32) (string, error), err error) {

	getAttrName, ok := attributemap.GetOIDMapper(vendorID)
	if ok {
		// vendorID is exist in registered vendors
		name, typ, mapperFunc = getAttrName(vsaTyp)
	} else {
		// cannot find vendorID in registered vendors so return attribute name in format "vendorID;vsaType" and type octets
		err = fmt.Errorf("found vendor-specific radius attribute with unknown vendor: %v", vendorID)
		name = fmt.Sprintf("%v;%v", vendorID, vsaTyp)
		typ = dict.AttributeOctets
	}

	if name == "" {
		// cannot find vsaType in vendor mapping so return attribute name in format "vendorID;vsaType" and type octets
		err = fmt.Errorf("found attribute for vendor %v with unknown type: %v", vendorID, vsaTyp)
		name = fmt.Sprintf("%v;%v", vendorID, vsaTyp)
		typ = dict.AttributeOctets
	}

	return
}

func CreateAttribute(typ string, value string) (radius.Type, radius.Attribute, error) {
	vendorID, oid, aTyp, mapperFunc, err := findAttrTypeByName(typ)

	if err != nil {
		return -1, nil, err
	}

	attr, err := encodeAttributeValue(aTyp, value, mapperFunc)
	if err != nil {
		return oid, nil, err
	}

	if vendorID == 0 {
		// standard(not vendor specific) attribute
		return oid, attr, nil
	}

	// innerOid and length must be byte and length is len(attr)+2
	// maximum valid len is 4bytes(vendorID) + 1byte(oid) + 1byte(length) + 249bytes(value) = 255
	if oid > 255 || len(attr) > 249 {
		return rfc2865.VendorSpecific_Type, nil, fmt.Errorf("oid and attribute length must be less than 255: oid:%q attrLen:%q", oid, len(attr)+2)
	}

	// valid vsa
	innerOID := byte(oid)
	length := byte(len(attr) + 2)
	innerAttr := []byte{innerOID, length}
	innerAttr = append(innerAttr, attr...)
	vsa, err := radius.NewVendorSpecific(uint32(vendorID), innerAttr)

	return rfc2865.VendorSpecific_Type, vsa, err
}
