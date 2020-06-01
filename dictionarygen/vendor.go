package dictionarygen

import (
	"io"
	"strconv"

	"bitbucket.parspooyesh.com/ibscgw/radius/dictionary"
)

func (g *Generator) genVendor(w io.Writer, vendor *dictionary.Vendor) {
	ident := identifier(vendor.Name)

	//attrOIDMap
	p(w)
	p(w, `var attrOIDMap = map[radius.Type]radius.NameType {`)
	for _, attr := range vendor.Attributes {
		valueMapping := "nil"
		for _, value := range vendor.Values {
			if value.Attribute == attr.Name {
				valueMapping = identifier(value.Attribute) + `_GetValueString`
			}
		}

		p(w, `	`, strconv.Itoa(attr.OID[0]), `:{ "`+attr.Name+`", `, strconv.Itoa(int(attr.Type)), `, `, valueMapping, `},`)
	}
	p(w, `}`)

	//attrNameMap
	p(w)
	p(w, `var attrNameMap = map[string]radius.OIDType {`)
	for _, attr := range vendor.Attributes {
		valueMapping := "nil"
		for _, value := range vendor.Values {
			if value.Attribute == attr.Name {
				valueMapping = identifier(value.Attribute) + `_GetValueNumber`
			}
		}

		p(w, `	`, `"`, attr.Name, `"`, `:{ `+strconv.Itoa(attr.OID[0])+`, `, strconv.Itoa(int(attr.Type)), `, `, valueMapping, `},`)
	}
	p(w, `}`)

	//GetAttrName function
	p(w)
	p(w, `func GetAttrName(T byte) (string, dictionary.AttributeType, func(uint32) (string, error)) {`)
	p(w, `	`, `name, ok := attrOIDMap[radius.Type(T)]`)
	p(w, `	`, `if ok {`)
	p(w, `	`, `	`, `return name.Name, name.T, name.ValueMapFunc`)
	p(w, `	`, `}`)
	p(w, `	`, `return "", 2, nil`)
	p(w, `}`)

	//GetAttrOID function
	p(w)
	p(w, `func GetAttrOID(name string) (radius.Type, dictionary.AttributeType, func(string) (uint32, error)) {`)
	p(w, `	`, `t, ok := attrNameMap[name]`)
	p(w, `	`, `if ok {`)
	p(w, `	`, `	`, `return t.OID, t.T, t.ValueMapFunc`)
	p(w, `	`, `}`)
	p(w, `	`, `return -1, dictionary.AttributeOctets, nil`)
	p(w, `}`)

	//Register Vendor attributeMap
	p(w)
	p(w, `func init() {`)
	p(w, `	`, `attributemap.RegisterVendor(`, `_`, ident, `_VendorID`, `, GetAttrName, GetAttrOID)`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_AddVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {`)
	p(w, `	var vsa radius.Attribute`)
	p(w, `	vendor := make(radius.Attribute, 2+len(attr))`)
	p(w, `	vendor[0] = typ`)
	p(w, `	vendor[1] = byte(len(vendor))`)
	p(w, `	copy(vendor[2:], attr)`)
	p(w, `	vsa, err = radius.NewVendorSpecific(_`, ident, `_VendorID, vendor)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	p.Add(rfc2865.VendorSpecific_Type, vsa)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_GetsVendor(p *radius.Packet, typ byte) (values []radius.Attribute) {`)
	p(w, `	for _, attr := range p.Attributes[rfc2865.VendorSpecific_Type] {`)
	p(w, `		vendorID, vsa, err := radius.VendorSpecific(attr)`)
	p(w, `		if err != nil || vendorID != _`, ident, `_VendorID {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		for len(vsa) >= 3 {`)
	p(w, `			vsaTyp, vsaLen := vsa[0], vsa[1]`)
	p(w, `			if int(vsaLen) > len(vsa) || vsaLen < 3 {`) // malformed
	p(w, `				break`)
	p(w, `			}`)
	p(w, `			if vsaTyp == typ {`)
	p(w, `				values = append(values, vsa[2:int(vsaLen)])`)
	p(w, `			}`)
	p(w, `			vsa = vsa[int(vsaLen):]`)
	p(w, `		}`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_LookupVendor(p *radius.Packet, typ byte) (attr radius.Attribute, ok bool) {`)
	p(w, `	for _, a := range p.Attributes[rfc2865.VendorSpecific_Type] {`)
	p(w, `		vendorID, vsa, err := radius.VendorSpecific(a)`)
	p(w, `		if err != nil || vendorID != _`, ident, `_VendorID {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		for len(vsa) >= 3 {`)
	p(w, `			vsaTyp, vsaLen := vsa[0], vsa[1]`)
	p(w, `			if int(vsaLen) > len(vsa) || vsaLen < 3 {`) // malformed
	p(w, `				break`)
	p(w, `			}`)
	p(w, `			if vsaTyp == typ {`)
	p(w, `				return vsa[2:int(vsaLen)], true`)
	p(w, `			}`)
	p(w, `			vsa = vsa[int(vsaLen):]`)
	p(w, `		}`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_SetVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {`)
	p(w, `	for i := 0; i < len(p.Attributes[rfc2865.VendorSpecific_Type]); {`)
	p(w, `		vendorID, vsa, err := radius.VendorSpecific(p.Attributes[rfc2865.VendorSpecific_Type][i])`)
	p(w, `		if err != nil || vendorID != _`, ident, `_VendorID {`)
	p(w, `			i++`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		for j := 0; len(vsa[j:]) >= 3; {`)
	p(w, `			vsaTyp, vsaLen := vsa[0], vsa[1]`)
	p(w, `			if int(vsaLen) > len(vsa[j:]) || vsaLen < 3 {`) // malformed
	p(w, `				i++`)
	p(w, `				break`)
	p(w, `			}`)
	p(w, `			if vsaTyp == typ {`)
	p(w, `				vsa = append(vsa[:j], vsa[j+int(vsaLen):]...)`)
	p(w, `			}`)
	p(w, `			j += int(vsaLen)`)
	p(w, `		}`)
	p(w, `		if len(vsa) > 0 {`)
	p(w, `			copy(p.Attributes[rfc2865.VendorSpecific_Type][i][4:], vsa)`)
	p(w, `			i++`)
	p(w, `		} else {`)
	p(w, `			p.Attributes[rfc2865.VendorSpecific_Type] = append(p.Attributes[rfc2865.VendorSpecific_Type][:i], p.Attributes[rfc2865.VendorSpecific_Type][i+i:]...)`)
	p(w, `		}`)
	p(w, `	}`)
	p(w, `	return _`, ident, `_AddVendor(p, typ, attr)`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_DelVendor(p *radius.Packet, typ byte) {`)
	p(w, `vsaLoop:`)
	p(w, `	for i := 0; i < len(p.Attributes[rfc2865.VendorSpecific_Type]); {`)
	p(w, `		attr := p.Attributes[rfc2865.VendorSpecific_Type][i]`)
	p(w, `		vendorID, vsa, err := radius.VendorSpecific(attr)`)
	p(w, `		if err != nil || vendorID != _`, ident, `_VendorID {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		offset := 0`)
	p(w, `		for len(vsa[offset:]) >= 3 {`)
	p(w, `			vsaTyp, vsaLen := vsa[offset], vsa[offset+1]`)
	p(w, `			if int(vsaLen) > len(vsa) || vsaLen < 3 {`) // malformed
	p(w, `				continue vsaLoop`)
	p(w, `			}`)
	p(w, `			if vsaTyp == typ {`)
	p(w, `				copy(vsa[offset:], vsa[offset+int(vsaLen):])`)
	p(w, `				vsa = vsa[:len(vsa)-int(vsaLen)]`)
	p(w, `			} else {`)
	p(w, `				offset += int(vsaLen)`)
	p(w, `			}`)
	p(w, `		}`)
	p(w, `		if offset == 0 {`)
	p(w, `			p.Attributes[rfc2865.VendorSpecific_Type] = append(p.Attributes[rfc2865.VendorSpecific_Type][:i], p.Attributes[rfc2865.VendorSpecific_Type][i+1:]...)`)
	p(w, `		} else {`)
	p(w, `			i++`)
	p(w, `		}`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)
}
