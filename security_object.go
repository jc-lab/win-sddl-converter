package winsddlconverter

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

type SecurityDescriptor struct {
	Control          SECURITY_DESCRIPTOR_CONTROL `json:"control"`
	Owner            string                      `json:"owner,omitempty"`
	Group            string                      `json:"group,omitempty"`
	DiscretionaryAcl *Acl                        `json:"dacl,omitempty"`
	SystemAcl        *Acl                        `json:"sacl,omitempty"`
}

type Acl struct {
	AclRevision uint8 `json:"aclRevision"`
	Aces        []Ace `json:"aces"`
}

type Ace struct {
	AceType    AceType          `json:"aceType"`
	AceFlags   []string         `json:"aceFlags"`
	AccessMask AccessMaskDetail `json:"accessMask"`
	Sid        string           `json:"sid"`
}

type AccessMaskDetail struct {
	Mask       uint32   `json:"mask"`
	Flags      []string `json:"flags"`
	HasUnknown bool     `json:"hasUnknown"`
}

func parseAceFlags(flags uint8) []string {
	var result []string
	if flags&OBJECT_INHERIT_ACE != 0 {
		result = append(result, "OI")
	}
	if flags&CONTAINER_INHERIT_ACE != 0 {
		result = append(result, "CI")
	}
	if flags&NO_PROPAGATE_INHERIT_ACE != 0 {
		result = append(result, "NP")
	}
	if flags&INHERIT_ONLY_ACE != 0 {
		result = append(result, "IO")
	}
	if flags&INHERITED_ACE != 0 {
		result = append(result, "ID")
	}
	if flags&SUCCESSFUL_ACCESS_ACE_FLAG != 0 {
		result = append(result, "SA")
	}
	if flags&FAILED_ACCESS_ACE_FLAG != 0 {
		result = append(result, "FA")
	}
	return result
}

type securityDescriptorParser struct {
	data []byte
}

func ParseBinary(data []byte) (*SecurityDescriptor, error) {
	parser := &securityDescriptorParser{data: data}
	return parser.Parse()
}

func (p *securityDescriptorParser) parseSid(offset int) (string, error) {
	if offset >= len(p.data) {
		return "", fmt.Errorf("invalid offset for SID parsing")
	}

	revision := p.data[offset]
	subAuthCount := p.data[offset+1]
	identifierAuthority := p.data[offset+2 : offset+8]

	// Always use numeric authority
	authValue := uint64(0)
	for i := 0; i < 6; i++ {
		authValue = (authValue << 8) | uint64(identifierAuthority[i])
	}
	authStr := fmt.Sprintf("%d", authValue)

	var sidParts []string
	sidParts = append(sidParts, fmt.Sprintf("S-%d-%s", revision, authStr))

	currentOffset := offset + 8
	for i := 0; i < int(subAuthCount); i++ {
		if currentOffset+4 > len(p.data) {
			return "", fmt.Errorf("invalid sub-authority data")
		}
		subAuth := uint32(p.data[currentOffset]) |
			uint32(p.data[currentOffset+1])<<8 |
			uint32(p.data[currentOffset+2])<<16 |
			uint32(p.data[currentOffset+3])<<24
		sidParts = append(sidParts, fmt.Sprintf("%d", subAuth))
		currentOffset += 4
	}

	// Construct full SID string
	fullSid := strings.Join(sidParts, "-")

	// Check if this is a well-known SID
	if wellKnownSid, exists := wellKnownSids[fullSid]; exists {
		return wellKnownSid, nil
	}

	return fullSid, nil
}

func (p *securityDescriptorParser) parseAcl(offset int) (*Acl, int, error) {
	if offset+8 >= len(p.data) {
		return nil, 0, fmt.Errorf("invalid offset for ACL parsing")
	}

	aclRevision := p.data[offset]
	aceCount := uint16(p.data[offset+4]) | uint16(p.data[offset+5])<<8

	currentOffset := offset + 8 // Skip ACL header
	aces := make([]Ace, 0, aceCount)

	for i := 0; i < int(aceCount); i++ {
		if currentOffset+4 >= len(p.data) {
			return nil, 0, fmt.Errorf("invalid ACE data")
		}

		aceType := AceType(p.data[currentOffset])
		aceFlags := p.data[currentOffset+1]
		aceSize := uint16(p.data[currentOffset+2]) | uint16(p.data[currentOffset+3])<<8

		if aceType == ACCESS_ALLOWED_ACE_TYPE || aceType == ACCESS_DENIED_ACE_TYPE || aceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE {
			if currentOffset+8 >= len(p.data) {
				return nil, 0, fmt.Errorf("invalid ACE access mask")
			}

			accessMask := uint32(p.data[currentOffset+4]) |
				uint32(p.data[currentOffset+5])<<8 |
				uint32(p.data[currentOffset+6])<<16 |
				uint32(p.data[currentOffset+7])<<24

			sid, err := p.parseSid(currentOffset + 8)
			if err != nil {
				return nil, 0, fmt.Errorf("error parsing SID in ACE: %v", err)
			}

			ace := Ace{
				AceType:    aceType,
				AceFlags:   parseAceFlags(aceFlags),
				AccessMask: ParseAccessMask(accessMask),
				Sid:        sid,
			}
			aces = append(aces, ace)
		}

		currentOffset += int(aceSize)
	}

	return &Acl{
		AclRevision: aclRevision,
		Aces:        aces,
	}, currentOffset, nil
}

func (p *securityDescriptorParser) Parse() (*SecurityDescriptor, error) {
	if len(p.data) < 20 {
		return nil, fmt.Errorf("invalid SECURITY_DESCRIPTOR data")
	}

	revision := p.data[0]
	if revision != 1 {
		return nil, fmt.Errorf("unsupported SECURITY_DESCRIPTOR revision: %d", revision)
	}

	sd := &SecurityDescriptor{}

	sd.Control = SECURITY_DESCRIPTOR_CONTROL(binary.LittleEndian.Uint16(p.data[2:4]))

	ownerOffset := uint32(p.data[4]) | uint32(p.data[5])<<8 |
		uint32(p.data[6])<<16 | uint32(p.data[7])<<24
	groupOffset := uint32(p.data[8]) | uint32(p.data[9])<<8 |
		uint32(p.data[10])<<16 | uint32(p.data[11])<<24
	saclOffset := uint32(p.data[12]) | uint32(p.data[13])<<8 |
		uint32(p.data[14])<<16 | uint32(p.data[15])<<24
	daclOffset := uint32(p.data[16]) | uint32(p.data[17])<<8 |
		uint32(p.data[18])<<16 | uint32(p.data[19])<<24

	if ownerOffset > 0 {
		ownerSid, err := p.parseSid(int(ownerOffset))
		if err != nil {
			return nil, fmt.Errorf("error parsing owner SID: %v", err)
		}
		sd.Owner = ownerSid
	}

	if groupOffset > 0 {
		groupSid, err := p.parseSid(int(groupOffset))
		if err != nil {
			return nil, fmt.Errorf("error parsing group SID: %v", err)
		}
		sd.Group = groupSid
	}

	if saclOffset > 0 {
		sacl, _, err := p.parseAcl(int(saclOffset))
		if err != nil {
			return nil, fmt.Errorf("error parsing SACL: %v", err)
		}
		sd.SystemAcl = sacl
	}

	if daclOffset > 0 {
		dacl, _, err := p.parseAcl(int(daclOffset))
		if err != nil {
			return nil, fmt.Errorf("error parsing DACL: %v", err)
		}
		sd.DiscretionaryAcl = dacl
	}

	return sd, nil
}

func (sd *SecurityDescriptor) ToJson() ([]byte, error) {
	return json.MarshalIndent(sd, "", "    ")
}

func (ace *Ace) ToSddlPart() string {
	var builder strings.Builder

	builder.WriteString("(")
	builder.WriteString(ace.AceType.String())
	builder.WriteString(";")

	for _, flag := range ace.AceFlags {
		builder.WriteString(flag)
	}
	builder.WriteString(";")
	if ace.AccessMask.HasUnknown {
		builder.WriteString(fmt.Sprintf("0x%x", ace.AccessMask.Mask))
	} else {
		for _, flag := range ace.AccessMask.Flags {
			builder.WriteString(flag)
		}
	}
	builder.WriteString(";")
	builder.WriteString(";")
	builder.WriteString(";")

	builder.WriteString(ace.Sid)

	builder.WriteString(")")

	return builder.String()
}

func (acl *Acl) ToSddlPart() string {
	var builder strings.Builder

	for _, ace := range acl.Aces {
		builder.WriteString(ace.ToSddlPart())
	}

	return builder.String()
}

func (sd *SecurityDescriptor) ToSddl() string {
	var builder strings.Builder

	builder.WriteString("O:")
	builder.WriteString(RawSidToString(sd.Owner))
	builder.WriteString("G:")
	builder.WriteString(RawSidToString(sd.Group))
	if sd.DiscretionaryAcl != nil && len(sd.DiscretionaryAcl.Aces) > 0 {
		builder.WriteString("D:")
		if (sd.Control & SE_DACL_PROTECTED) != 0 {
			builder.WriteString("P")
		}
		if (sd.Control & SE_DACL_AUTO_INHERITED) != 0 {
			builder.WriteString("AI")
		}
		builder.WriteString(sd.DiscretionaryAcl.ToSddlPart())
	}
	if sd.SystemAcl != nil && len(sd.SystemAcl.Aces) > 0 {
		builder.WriteString("S:")
		if (sd.Control & SE_SACL_PROTECTED) != 0 {
			builder.WriteString("P")
		}
		if (sd.Control & SE_SACL_AUTO_INHERITED) != 0 {
			builder.WriteString("AI")
		}
		builder.WriteString(sd.SystemAcl.ToSddlPart())
	}

	return builder.String()
}
