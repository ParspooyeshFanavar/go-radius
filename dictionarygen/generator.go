package dictionarygen

import (
	"bytes"
	"errors"
	"fmt"
	"go/format"
	"net"
	"strconv"

	"github.com/ParspooyeshFanavar/go-radius/dictionary"
)

type externalAttribute struct {
	Attribute  string
	ImportPath string

	Values []*dictionary.Value
}

type Generator struct {
	// Output package name.
	Package string
	// Attributes that will be ignored during generation.
	IgnoredAttributes []string
	// Map of external attributes to import path where the attribute is
	// defined.
	ExternalAttributes map[string]string
}

func (g *Generator) Generate(dict *dictionary.Dictionary) ([]byte, error) {

	attrs := make([]*dictionary.Attribute, 0, len(dict.Attributes))

	ignoredAttributes := make(map[string]struct{}, len(g.IgnoredAttributes))
	for _, attrName := range g.IgnoredAttributes {
		ignoredAttributes[attrName] = struct{}{}
	}

	attrIdents := map[string]*dictionary.Attribute{}

	baseImports := map[string]struct{}{}

	for _, attr := range dict.Attributes {
		if _, ignored := ignoredAttributes[attr.Name]; ignored {
			continue
		}

		invalid := false
		if len(attr.OID) != 1 {
			invalid = true
		}
		if attr.Size.Valid {
			if attr.Type == dictionary.AttributeString || attr.Type == dictionary.AttributeOctets {
				baseImports["errors"] = struct{}{}
			} else {
				invalid = true
			}
		}
		if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int != dictionary.EncryptUserPassword && attr.FlagEncrypt.Int != dictionary.EncryptTunnelPassword {
			invalid = true
		}
		if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
			baseImports["crypto/rand"] = struct{}{}
		}
		if attr.FlagConcat.Valid && attr.FlagConcat.Bool && ((attr.Type != dictionary.AttributeOctets && attr.Type != dictionary.AttributeString) || attr.FlagEncrypt.Valid || attr.FlagHasTag.Valid || attr.Size.Valid) {
			invalid = true
		}
		if attr.FlagHasTag.Valid && attr.FlagHasTag.Bool && !(attr.Type == dictionary.AttributeOctets || attr.Type == dictionary.AttributeString || attr.Type == dictionary.AttributeInteger) {
			invalid = true
		}

		switch attr.Type {
		case dictionary.AttributeString:
		case dictionary.AttributeOctets:
		case dictionary.AttributeIPAddr, dictionary.AttributeIPv6Addr, dictionary.AttributeIPv6Prefix, dictionary.AttributeIFID:
			baseImports["net"] = struct{}{}
		case dictionary.AttributeDate:
			baseImports["time"] = struct{}{}
		case dictionary.AttributeShort, dictionary.AttributeInteger, dictionary.AttributeInteger64:
			baseImports["strconv"] = struct{}{}
		case dictionary.AttributeVSA:
		case dictionary.AttributeByte:
			baseImports["errors"] = struct{}{}
		default:
			invalid = true
		}

		ident := identifier(attr.Name)
		if existingAttr, ok := attrIdents[ident]; ok {
			return nil, fmt.Errorf("dictionarygen: conflicting identifier between %s (%s) and %s (%s)", existingAttr.Name, existingAttr.OID, attr.Name, attr.OID)
		}
		attrIdents[ident] = attr

		if invalid {
			return nil, errors.New("dictionarygen: cannot generate code for attribute " + attr.Name)
		}

		attrs = append(attrs, attr)
	}

	if len(dict.Values) > 0 {
		baseImports["fmt"] = struct{}{}
	}

	dictionary.SortAttributes(attrs)

	externalAttributes := make([]*externalAttribute, 0, len(g.ExternalAttributes))
	for attribute, importPath := range g.ExternalAttributes {
		externalAttributes = append(externalAttributes, &externalAttribute{
			Attribute:  attribute,
			ImportPath: importPath,
		})
	}
	sortExternalAttributes(externalAttributes)

	values := make([]*dictionary.Value, 0, len(dict.Values))
	for _, value := range dict.Values {
		if _, ignored := ignoredAttributes[value.Attribute]; ignored {
			continue
		}

		var isLocalAttr bool
		for _, attr := range attrs {
			if value.Attribute == attr.Name {
				isLocalAttr = true
				break
			}
		}
		if isLocalAttr {
			values = append(values, value)
			continue
		}

		var ea *externalAttribute
		for _, exAttr := range externalAttributes {
			if value.Attribute == exAttr.Attribute {
				ea = exAttr
				break
			}
		}
		if ea == nil {
			return nil, errors.New("dictionarygen: unknown attribute " + value.Attribute)
		}

		ea.Values = append(ea.Values, value)
	}
	dictionary.SortValues(values)

	vendors := make([]*dictionary.Vendor, 0, len(dict.Vendors))
	for _, vendor := range dict.Vendors {
		if vendor.GetLengthOctets() != 1 || vendor.GetTypeOctets() != 1 {
			return nil, errors.New("dictionarygen: cannot generate code for " + vendor.Name)
		}

		for _, attr := range vendor.Attributes {
			if _, ignored := ignoredAttributes[attr.Name]; ignored {
				continue
			}

			invalid := false
			if len(attr.OID) != 1 {
				invalid = true
			}
			if attr.Size.Valid {
				if attr.Type == dictionary.AttributeString || attr.Type == dictionary.AttributeOctets {
					baseImports["errors"] = struct{}{}
				} else {
					invalid = true
				}
			}
			if attr.FlagEncrypt.Valid &&
				attr.FlagEncrypt.Int != dictionary.EncryptUserPassword &&
				attr.FlagEncrypt.Int != dictionary.EncryptTunnelPassword &&
				attr.FlagEncrypt.Int != dictionary.EncryptAscendProprietaryPassword {
				invalid = true
			}
			if attr.FlagEncrypt.Valid && attr.FlagEncrypt.Int == dictionary.EncryptTunnelPassword {
				baseImports["crypto/rand"] = struct{}{}
			}
			if attr.FlagConcat.Valid && attr.FlagConcat.Bool {
				invalid = true
			}
			if attr.FlagHasTag.Valid && attr.FlagHasTag.Bool && !(attr.Type == dictionary.AttributeOctets || attr.Type == dictionary.AttributeString || attr.Type == dictionary.AttributeInteger) {
				invalid = true
			}

			switch attr.Type {
			case dictionary.AttributeString:
			case dictionary.AttributeOctets:
			case dictionary.AttributeABinary:
			case dictionary.AttributeIPAddr, dictionary.AttributeIPv6Addr, dictionary.AttributeIPv6Prefix, dictionary.AttributeIFID:
				baseImports["net"] = struct{}{}
			case dictionary.AttributeDate:
				baseImports["time"] = struct{}{}
			case dictionary.AttributeShort, dictionary.AttributeInteger, dictionary.AttributeInteger64:
				baseImports["strconv"] = struct{}{}
			case dictionary.AttributeByte:
				baseImports["errors"] = struct{}{}
			default:
				invalid = true
			}

			ident := identifier(attr.Name)
			if existingAttr, ok := attrIdents[ident]; ok {
				return nil, fmt.Errorf("dictionarygen: conflicting identifier between %s (%s) and %s (%s)", existingAttr.Name, existingAttr.OID, attr.Name, attr.OID)
			}
			attrIdents[ident] = attr

			if invalid {
				return nil, errors.New("dictionarygen: cannot generate code for " + vendor.Name + " vendor attribute " + attr.Name)
			}
		}

		if len(vendor.Values) > 0 {
			baseImports["fmt"] = struct{}{}
		}

		vendorAttributes := make([]*dictionary.Attribute, len(vendor.Attributes))
		copy(vendorAttributes, vendor.Attributes)
		dictionary.SortAttributes(vendorAttributes)

		vendorValues := make([]*dictionary.Value, len(vendor.Values))
		copy(vendorValues, vendor.Values)
		dictionary.SortValues(vendorValues)

		vendors = append(vendors, &dictionary.Vendor{
			Name:   vendor.Name,
			Number: vendor.Number,

			TypeOctets:   vendor.TypeOctets,
			LengthOctets: vendor.LengthOctets,

			Attributes: vendorAttributes,
			Values:     vendorValues,
		})
	}
	dictionary.SortVendors(vendors)

	var w bytes.Buffer

	p(&w, `// Code generated by radius-dict-gen. DO NOT EDIT.`)
	p(&w)
	p(&w, `package `, g.Package)

	// Imports
	p(&w)
	p(&w, `import (`)
	for imprt := range baseImports {
		p(&w, `	`+strconv.Quote(imprt))
	}
	if len(attrs) > 0 || len(vendors) > 0 {
		p(&w)
		p(&w, `	"github.com/ParspooyeshFanavar/go-radius"`)
	}
	if len(vendors) > 0 {
		p(&w, `	"github.com/ParspooyeshFanavar/go-radius/rfc2865"`)
		p(&w, `	"github.com/ParspooyeshFanavar/go-radius/dictionary"`)
		p(&w, `	"github.com/ParspooyeshFanavar/go-radius/attributemap"`)
	}
	if len(externalAttributes) > 0 {
		printedNewLine := false
		for _, exAttr := range externalAttributes {
			if len(exAttr.Values) > 0 {
				if !printedNewLine {
					p(&w)
					printedNewLine = true
				}
				p(&w, `	. `, strconv.Quote(exAttr.ImportPath))
			}
		}
	}
	p(&w, `)`)

	// Attribute types
	if len(attrs) > 0 {
		p(&w)
		p(&w, `const (`)
		for _, attr := range attrs {
			p(&w, `	`, identifier(attr.Name), `_Type radius.Type = `, strconv.Itoa(attr.OID[0]))
		}
		p(&w, `)`)
	}

	if len(vendors) > 0 {
		p(&w)
		p(&w, `const (`)
		for _, vendor := range vendors {
			p(&w, `	_`, identifier(vendor.Name), `_VendorID = `, strconv.Itoa(vendor.Number))
		}
		p(&w, `)`)
	}

	for _, exAttr := range externalAttributes {
		p(&w)
		p(&w, `func init() {`)
		for _, value := range exAttr.Values {
			attrIdent := identifier(value.Attribute)
			valueIdent := identifier(value.Name)
			p(&w, `	`, attrIdent, `_Strings[`, attrIdent, `_Value_`, valueIdent, `] = `, strconv.Quote(value.Name))
		}
		p(&w, `}`)

		p(&w)
		p(&w, `const (`)
		for _, value := range exAttr.Values {
			attrIdent := identifier(value.Attribute)
			valueIdent := identifier(value.Name)
			p(&w, `	`, attrIdent, `_Value_`, valueIdent, ` `, attrIdent, ` = `, strconv.Itoa(value.Number))
		}
		p(&w, `)`)
	}

	////attrOIDMap
	//p(&w)
	//p(&w, `var attrOIDMap = map[radius.Type]radius.NameType {`)
	//for _, attr := range dict.Attributes {
	//	valueMapping := "nil"
	//	for _, value := range dict.Values {
	//		if value.Attribute == attr.Name {
	//			valueMapping = identifier(value.Attribute) + `_GetValueString`
	//		}
	//	}
	//
	//	p(&w, `	`, strconv.Itoa(attr.OID[0]), `:{ "`+attr.Name+`", `, strconv.Itoa(int(attr.Type)), `, `, valueMapping, `},`)
	//}
	//p(&w, `}`)
	//
	////attrNameMap
	//p(&w)
	//p(&w, `var attrNameMap = map[string]radius.OIDType {`)
	//for _, attr := range dict.Attributes {
	//	valueMapping := "nil"
	//	for _, value := range dict.Values {
	//		if value.Attribute == attr.Name {
	//			valueMapping = identifier(value.Attribute) + `_GetValueNumber`
	//		}
	//	}
	//
	//	p(&w, `	`, `"`, attr.Name, `"`, `:{ `+strconv.Itoa(attr.OID[0])+`, `, strconv.Itoa(int(attr.Type)), `, `, valueMapping, `},`)
	//}
	//p(&w, `}`)
	//
	////GetAttrName function
	//p(&w)
	//p(&w, `func GetAttrName(T byte) (string, dictionary.AttributeType) {`)
	//p(&w, `	`, `name, ok := attrOIDMap[radius.Type(T)]`)
	//p(&w, `	`, `if ok {`)
	//p(&w, `	`, `	`, `return name.Name, name.T`)
	//p(&w, `	`, `}`)
	//p(&w, `	`, `return "", 2`)
	//p(&w, `}`)
	//
	////GetAttrOID function
	//p(&w)
	//p(&w, `func GetAttrOID(name string) (radius.Type, dictionary.AttributeType) {`)
	//p(&w, `	`, `t, ok := attrNameMap[name]`)
	//p(&w, `	`, `if ok {`)
	//p(&w, `	`, `	`, `return t.OID, t.T`)
	//p(&w, `	`, `}`)
	//p(&w, `	`, `return -1, dictionary.AttributeOctets`)
	//p(&w, `}`)

	for _, attr := range attrs {
		switch attr.Type {
		case dictionary.AttributeString, dictionary.AttributeOctets, dictionary.AttributeABinary:
			if attr.FlagConcat.Valid && attr.FlagConcat.Bool {
				g.genAttributeStringOctetsConcat(&w, attr)
			} else {
				g.genAttributeStringOctets(&w, attr, nil)
			}
		case dictionary.AttributeIPAddr:
			g.genAttributeIPAddr(&w, attr, nil, net.IPv4len)
		case dictionary.AttributeIPv6Addr:
			g.genAttributeIPAddr(&w, attr, nil, net.IPv6len)
		case dictionary.AttributeIPv6Prefix:
			g.genAttributeIPv6Prefix(&w, attr, nil)
		case dictionary.AttributeDate:
			g.genAttributeDate(&w, attr, nil)
		case dictionary.AttributeShort:
			g.genAttributeInteger(&w, attr, values, 16, nil)
		case dictionary.AttributeInteger:
			g.genAttributeInteger(&w, attr, values, 32, nil)
		case dictionary.AttributeIFID:
			g.genAttributeIFID(&w, attr, nil)
		case dictionary.AttributeVSA:
			// skip
		case dictionary.AttributeInteger64:
			g.genAttributeInteger(&w, attr, values, 64, nil)
		case dictionary.AttributeByte:
			g.genAttributeByte(&w, attr, values, nil)
		}
	}

	for _, vendor := range vendors {
		g.genVendor(&w, vendor)
		for _, attr := range vendor.Attributes {
			switch attr.Type {
			case dictionary.AttributeString, dictionary.AttributeOctets, dictionary.AttributeABinary:
				g.genAttributeStringOctets(&w, attr, vendor)
			case dictionary.AttributeIPAddr:
				g.genAttributeIPAddr(&w, attr, vendor, net.IPv4len)
			case dictionary.AttributeIPv6Addr:
				g.genAttributeIPAddr(&w, attr, vendor, net.IPv6len)
			case dictionary.AttributeIPv6Prefix:
				g.genAttributeIPv6Prefix(&w, attr, vendor)
			case dictionary.AttributeDate:
				g.genAttributeDate(&w, attr, vendor)
			case dictionary.AttributeIFID:
				g.genAttributeIFID(&w, attr, vendor)
			case dictionary.AttributeShort:
				g.genAttributeInteger(&w, attr, vendor.Values, 16, vendor)
			case dictionary.AttributeInteger:
				g.genAttributeInteger(&w, attr, vendor.Values, 32, vendor)
			case dictionary.AttributeInteger64:
				g.genAttributeInteger(&w, attr, vendor.Values, 64, vendor)
			case dictionary.AttributeByte:
				g.genAttributeByte(&w, attr, vendor.Values, vendor)
			}
		}
	}

	formatted, err := format.Source(w.Bytes())
	if err != nil {
		return nil, err
	}
	return formatted, nil
}
