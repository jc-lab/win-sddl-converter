package winsddlconverter

import "fmt"

type SECURITY_DESCRIPTOR_CONTROL uint16

// Constants for type SECURITY_DESCRIPTOR_CONTROL
const (
	SE_OWNER_DEFAULTED       SECURITY_DESCRIPTOR_CONTROL = 0x0001
	SE_GROUP_DEFAULTED       SECURITY_DESCRIPTOR_CONTROL = 0x0002
	SE_DACL_PRESENT          SECURITY_DESCRIPTOR_CONTROL = 0x0004
	SE_DACL_DEFAULTED        SECURITY_DESCRIPTOR_CONTROL = 0x0008
	SE_SACL_PRESENT          SECURITY_DESCRIPTOR_CONTROL = 0x0010
	SE_SACL_DEFAULTED        SECURITY_DESCRIPTOR_CONTROL = 0x0020
	SE_DACL_AUTO_INHERIT_REQ SECURITY_DESCRIPTOR_CONTROL = 0x0100
	SE_SACL_AUTO_INHERIT_REQ SECURITY_DESCRIPTOR_CONTROL = 0x0200
	SE_DACL_AUTO_INHERITED   SECURITY_DESCRIPTOR_CONTROL = 0x0400
	SE_SACL_AUTO_INHERITED   SECURITY_DESCRIPTOR_CONTROL = 0x0800
	SE_DACL_PROTECTED        SECURITY_DESCRIPTOR_CONTROL = 0x1000
	SE_SACL_PROTECTED        SECURITY_DESCRIPTOR_CONTROL = 0x2000
	SE_RM_CONTROL_VALID      SECURITY_DESCRIPTOR_CONTROL = 0x4000
	SE_SELF_RELATIVE         SECURITY_DESCRIPTOR_CONTROL = 0x8000
)

// Constants for ACE flags
const (
	OBJECT_INHERIT_ACE         = 0x01
	CONTAINER_INHERIT_ACE      = 0x02
	NO_PROPAGATE_INHERIT_ACE   = 0x04
	INHERIT_ONLY_ACE           = 0x08
	INHERITED_ACE              = 0x10
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
	FAILED_ACCESS_ACE_FLAG     = 0x80
)

type AceType uint8

const (
	ACCESS_MIN_MS_ACE_TYPE                  AceType = 0x0
	ACCESS_ALLOWED_ACE_TYPE                 AceType = 0x0
	ACCESS_DENIED_ACE_TYPE                  AceType = 0x1
	SYSTEM_AUDIT_ACE_TYPE                   AceType = 0x2
	SYSTEM_ALARM_ACE_TYPE                   AceType = 0x3
	ACCESS_MAX_MS_V2_ACE_TYPE               AceType = 0x3
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE        AceType = 0x4
	ACCESS_MAX_MS_V3_ACE_TYPE               AceType = 0x4
	ACCESS_MIN_MS_OBJECT_ACE_TYPE           AceType = 0x5
	ACCESS_ALLOWED_OBJECT_ACE_TYPE          AceType = 0x5
	ACCESS_DENIED_OBJECT_ACE_TYPE           AceType = 0x6
	ACCESS_AUDIT_OBJECT_ACE_TYPE            AceType = 0x7
	ACCESS_ALARM_OBJECT_ACE_TYPE            AceType = 0x8
	ACCESS_MAX_MS_V4_ACE_TYPE               AceType = 0x8
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE        AceType = 0x9
	ACCESS_DENIED_CALLBACK_ACE_TYPE         AceType = 0xa
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE AceType = 0xb
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  AceType = 0xc
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE          AceType = 0xd
	SYSTEM_ALARM_CALLBACK_ACE_TYPE          AceType = 0xe
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   AceType = 0xf
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   AceType = 0x10
	SYSTEM_MANDATORY_LABEL_ACE_TYPE         AceType = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      AceType = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        AceType = 0x13
	SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE     AceType = 0x14
	ACCESS_MAX_MS_V5_ACE_TYPE               AceType = 0x14
)

func (v AceType) String() string {
	switch v {
	case ACCESS_ALLOWED_ACE_TYPE:
		return "A"
	case ACCESS_DENIED_ACE_TYPE:
		return "D"
	case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
		return "ML"
	default:
		return "?"
	}
}

func ParseAceType(v string) (AceType, error) {
	switch v {
	case "A":
		return ACCESS_ALLOWED_ACE_TYPE, nil
	case "D":
		return ACCESS_DENIED_ACE_TYPE, nil
	case "ML":
		return SYSTEM_MANDATORY_LABEL_ACE_TYPE, nil
	default:
		return 0, fmt.Errorf("unsupported ACE type: %s", v)
	}
}

// Well-known SID to SDDL mapping
var wellKnownSids = map[string]string{
	"S-1-0-0": "NO", // Nobody
	"S-1-1-0": "WD", // Everyone
	"S-1-2-0": "LG", // Local
	"S-1-3-0": "CO", // Creator Owner
	"S-1-3-1": "CG", // Creator Group
	"S-1-5-1": "DU", // Dialup
	"S-1-5-2": "NU", // Network
	"S-1-5-3": "BG", // Batch
	"S-1-5-4": "IU", // Interactive
	"S-1-5-6": "SU", // Service
	"S-1-5-7": "AN", // Anonymous
	"S-1-5-8": "PS", // Proxy
	"S-1-5-9": "ED", // Enterprise Domain Controllers
	//"S-1-5-10":     "SELF", // Self | FIXME:
	"S-1-5-11":     "AU", // Authenticated Users
	"S-1-5-12":     "RC", // Restricted Code
	"S-1-5-32-544": "BA", // Builtin Administrator
	"S-1-5-32-545": "BU", // Builtin Users
	"S-1-5-32-546": "BG", // Builtin Guests
	"S-1-5-32-547": "PU", // Power Users
	"S-1-5-32-548": "AO", // Account Operators
	"S-1-5-32-549": "SO", // Server Operators
	"S-1-5-32-550": "PO", // Printer Operators
	"S-1-5-32-551": "BO", // Backup Operators
	"S-1-5-32-552": "RE", // Replicator
	"S-1-5-32-554": "RU", // Builtin\Pre-Windows 2000 Compatible Access
	"S-1-5-32-555": "RD", // Remote Desktop Users
	"S-1-5-32-556": "NO", // Network Configuration Operators
	"S-1-5-32-558": "MU", // Performance Monitor Users
	"S-1-5-32-559": "LU", // Performance Log Users
	"S-1-5-32-568": "IS", // IIS_IUSRS
	"S-1-5-32-569": "CY", // Cryptographic Operators
	"S-1-5-32-573": "ER", // Event Log Readers
	"S-1-5-32-574": "CD", // Certificate Service DCOM Access
	"S-1-5-18":     "SY", // Local System
	"S-1-5-19":     "LS", // Local Service
	"S-1-5-20":     "NS", // Network Service
	"S-1-15-2-1":   "AC", // All Application Packages
}

var wellKnownSidsReverse map[string]string

func init() {
	wellKnownSidsReverse = make(map[string]string)
	for key, value := range wellKnownSids {
		wellKnownSidsReverse[value] = key
	}
}

// RawSidToString sid to sid or alias
func RawSidToString(input string) string {
	s, ok := wellKnownSids[input]
	if ok {
		return s
	}
	return input
}

// GetRawSid sid or alias to sid
func GetRawSid(input string) string {
	s, ok := wellKnownSidsReverse[input]
	if ok {
		return s
	}
	return input
}
