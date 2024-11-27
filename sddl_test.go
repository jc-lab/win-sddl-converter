package winsddlconverter

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseSDDL(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		want    *SecurityDescriptor
		wantErr bool
	}{
		{
			"C:/testdir-1",
			"O:S-1-5-21-920909269-1353440977-3059239504-1001G:S-1-5-21-920909269-1353440977-3059239504-513D:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)",
			&SecurityDescriptor{
				Control: SE_DACL_AUTO_INHERITED,
				Owner:   "S-1-5-21-920909269-1353440977-3059239504-1001",
				Group:   "S-1-5-21-920909269-1353440977-3059239504-513",
				DiscretionaryAcl: &Acl{
					AclRevision: 2,
					Aces: []Ace{
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI", "ID"},
							AccessMask: AccessMaskDetail{
								Mask:       2032127,
								Flags:      []string{"FA"},
								HasUnknown: false,
							},
							Sid: "BA",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI", "ID"},
							AccessMask: AccessMaskDetail{
								Mask:       2032127,
								Flags:      []string{"FA"},
								HasUnknown: false,
							},
							Sid: "SY",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI", "ID"},
							AccessMask: AccessMaskDetail{
								Mask:       1179817,
								Flags:      []string{"RC", "SY"},
								HasUnknown: true,
							},
							Sid: "BU",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"ID"},
							AccessMask: AccessMaskDetail{
								Mask:       1245631,
								Flags:      []string{"SD", "RC", "SY"},
								HasUnknown: true,
							},
							Sid: "AU",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI", "IO", "ID"},
							AccessMask: AccessMaskDetail{
								Mask:       3758161920,
								Flags:      []string{"SD", "GX", "GW", "GR"},
								HasUnknown: false,
							},
							Sid: "AU",
						},
					},
				},
			},
			false,
		},
		{
			"C:/testdir-2",
			"O:S-1-5-21-920909269-1353440977-3059239504-1001G:S-1-5-21-920909269-1353440977-3059239504-513D:(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)",
			&SecurityDescriptor{
				Owner: "S-1-5-21-920909269-1353440977-3059239504-1001",
				Group: "S-1-5-21-920909269-1353440977-3059239504-513",
				DiscretionaryAcl: &Acl{
					AclRevision: 2,
					Aces: []Ace{
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI", "ID"},
							AccessMask: AccessMaskDetail{
								Mask:       2032127,
								Flags:      []string{"FA"},
								HasUnknown: false,
							},
							Sid: "BA",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI", "ID"},
							AccessMask: AccessMaskDetail{
								Mask:       2032127,
								Flags:      []string{"FA"},
								HasUnknown: false,
							},
							Sid: "SY",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI", "ID"},
							AccessMask: AccessMaskDetail{
								Mask:       1179817,
								Flags:      []string{"RC", "SY"},
								HasUnknown: true,
							},
							Sid: "BU",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"ID"},
							AccessMask: AccessMaskDetail{
								Mask:       1245631,
								Flags:      []string{"SD", "RC", "SY"},
								HasUnknown: true,
							},
							Sid: "AU",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI", "IO", "ID"},
							AccessMask: AccessMaskDetail{
								Mask:       3758161920,
								Flags:      []string{"SD", "GX", "GW", "GR"},
								HasUnknown: false,
							},
							Sid: "AU",
						},
					},
				},
			},
			false,
		},
		{
			"posix 0764",
			"O:BAG:SYD:PAI(A;OICI;FA;;;CO)(A;OICI;GWGR;;;CG)(A;OICI;GRGX;;;WD)",
			&SecurityDescriptor{
				Control: SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED,
				Owner:   "S-1-5-32-544",
				Group:   "S-1-5-18",
				DiscretionaryAcl: &Acl{
					AclRevision: 2,
					Aces: []Ace{
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI"},
							AccessMask: AccessMaskDetail{
								Mask:       FILE_ALL_ACCESS,
								Flags:      []string{"FA"},
								HasUnknown: false,
							},
							Sid: "CO",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI"},
							AccessMask: AccessMaskDetail{
								Mask:       GENERIC_WRITE | GENERIC_READ,
								Flags:      []string{"GW", "GR"},
								HasUnknown: false,
							},
							Sid: "CG",
						},
						{
							AceType:  ACCESS_ALLOWED_ACE_TYPE,
							AceFlags: []string{"OI", "CI"},
							AccessMask: AccessMaskDetail{
								Mask:       GENERIC_READ | GENERIC_EXECUTE,
								Flags:      []string{"GR", "GX"},
								HasUnknown: false,
							},
							Sid: "WD",
						},
					},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSDDL(tt.sddl)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSDDL() error = %+v, wantErr %+v", err, tt.wantErr)
				return
			}
			gotJson := toJson(t, got)
			wantJson := toJson(t, tt.want)
			assert.Equal(t, wantJson, gotJson)
		})
	}
}

func toJson(t *testing.T, a interface{}) string {
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
