package translator

import (
	"reflect"
	"testing"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/dictionary"
)

func TestCreateAttribute(t *testing.T) {
	type args struct {
		typ   string
		value string
	}
	tests := []struct {
		name    string
		args    args
		want    radius.Type
		want1   radius.Attribute
		wantErr bool
	}{
		{name: "translate username", args: args{typ: `User-Name`, value: `parspooyesh`}, want: 1, want1: []byte(`parspooyesh`), wantErr: false},
		{name: "translate cisco avpair", args: args{typ: `Cisco-AVPair`, value: `client-mac-address=14cc.2065.5261`}, want: 26, want1: append([]byte{0, 0, 0, 9, 1, 35}, []byte(`client-mac-address=14cc.2065.5261`)...), wantErr: false},
		{name: "wrong translate username", args: args{typ: `UserName`, value: `parspooyesh`}, want: -1, want1: nil, wantErr: true},
		{name: "translate Service Type", args: args{typ: `Service-Type`, value: `Login-User`}, want: 6, want1: []byte{0, 0, 0, 1}, wantErr: false},
		{name: "translate Sip-Method", args: args{typ: `Sip-Method`, value: `Invite`}, want: 101, want1: []byte{0, 0, 0, 1}, wantErr: false},
		{name: "translate unknown", args: args{typ: `unknown`, value: `123`}, want: -1, want1: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := CreateAttribute(tt.args.typ, tt.args.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateAttribute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CreateAttribute() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("CreateAttribute() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestTranslateAttributes(t *testing.T) {
	type args struct {
		attributes *radius.Attributes
	}
	tests := []struct {
		name string
		args args
		want *map[string][]string
	}{
		{
			name: "translate attributes",
			args: args{attributes: &radius.Attributes{1: {[]byte(`parspooyesh`)}}},
			want: &map[string][]string{"User-Name": {`parspooyesh`}},
		},
		{
			name: "translate attributes with vsa",
			args: args{attributes: &radius.Attributes{1: {[]byte(`parspooyesh`)}, 26: {append([]byte{0, 0, 0, 9, 1, 35}, []byte(`client-mac-address=14cc.2065.5261`)...)}}},
			want: &map[string][]string{"User-Name": {`parspooyesh`}, "Cisco-AVPair": {"client-mac-address=14cc.2065.5261"}},
		},
		{
			name: "translate attributes with vsa unknown vendor",
			args: args{attributes: &radius.Attributes{1: {[]byte(`parspooyesh`)}, 26: {append([]byte{0, 0, 255, 255, 78, 5}, []byte(`abc`)...)}}},
			want: &map[string][]string{"User-Name": {`parspooyesh`}, "65535;78": {"0x616263"}},
		},
		{
			name: "translate sip attributes",
			args: args{attributes: &radius.Attributes{1: {[]byte(`parspooyesh`)}, 101: {[]byte{0, 0, 0, 1}}}},
			want: &map[string][]string{"User-Name": {`parspooyesh`}, "Sip-Method": {"Invite"}},
		},
		{
			name: "translate attributes with mapped value",
			args: args{attributes: &radius.Attributes{6: {[]byte{0, 0, 0, 1}}, 26: {append([]byte{0, 0, 255, 255, 78, 5}, []byte(`abc`)...)}}},
			want: &map[string][]string{`Service-Type`: {`Login-User`}, "65535;78": {"0x616263"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TranslateAttributes(tt.args.attributes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TranslateAttributes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTranslateMapToAttributes(t *testing.T) {
	type args struct {
		attrMap *map[string][]string
	}
	tests := []struct {
		name string
		args args
		want *radius.Attributes
	}{
		{
			name: "translate map",
			args: args{attrMap: &map[string][]string{"User-Name": {`parspooyesh`}}},
			want: &radius.Attributes{1: {[]byte(`parspooyesh`)}},
		},

		{
			name: "translate map with vsa",
			args: args{attrMap: &map[string][]string{"User-Name": {`parspooyesh`}, "Cisco-AVPair": {"client-mac-address=14cc.2065.5261"}, "Cisco-NAS-Port": {"1812"}}},
			want: &radius.Attributes{1: {[]byte(`parspooyesh`)}, 26: {append([]byte{0, 0, 0, 9, 1, 35}, []byte(`client-mac-address=14cc.2065.5261`)...), append([]byte{0, 0, 0, 9, 2, 6}, []byte(`1812`)...)}},
		},

		{
			name: "translate map with multiple vsa",
			args: args{attrMap: &map[string][]string{"User-Name": {`parspooyesh`}, "Cisco-AVPair": {"client-mac-address=14cc.2065.5261"}}},
			want: &radius.Attributes{1: {[]byte(`parspooyesh`)}, 26: {append([]byte{0, 0, 0, 9, 1, 35}, []byte(`client-mac-address=14cc.2065.5261`)...)}},
		},

		{
			name: "translate map with unknown attribute",
			args: args{attrMap: &map[string][]string{"User-Name": {`parspooyesh`}, "unknown": {"0x616263"}}},
			want: &radius.Attributes{1: {[]byte(`parspooyesh`)}},
		},

		{
			name: "translate map with numeric key attribute",
			args: args{attrMap: &map[string][]string{"User-Name": {`parspooyesh`}, `758;25`: {"0x616263"}}},
			want: &radius.Attributes{1: {[]byte(`parspooyesh`)}, 26: {append([]byte{0, 0, 0x02, 0xf6, 25, 5}, []byte(`abc`)...)}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TranslateMapToAttributes(tt.args.attrMap); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TranslateMapToAttributes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getVSANameType(t *testing.T) {
	type args struct {
		vendorID uint32
		vsaTyp   byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   dictionary.AttributeType
		wantErr bool
	}{
		{name: "get cisco vsa name and type", args: args{vendorID: CiscoVendorID, vsaTyp: 1}, want: `Cisco-AVPair`, want1: dictionary.AttributeString, wantErr: false},
		{name: "get unknown type vsa name and type", args: args{vendorID: MikrotikVendorID, vsaTyp: 255}, want: `14988;255`, want1: dictionary.AttributeOctets, wantErr: true},
		{name: "get unknown vendor vsa name and type", args: args{vendorID: 758, vsaTyp: 25}, want: `758;25`, want1: dictionary.AttributeOctets, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, _, err := getVSANameType(tt.args.vendorID, tt.args.vsaTyp)
			if (err != nil) != tt.wantErr {
				t.Errorf("getVSANameType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getVSANameType() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getVSANameType() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
