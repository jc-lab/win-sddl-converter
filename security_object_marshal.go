package winsddlconverter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
)

func (sd *SecurityDescriptor) ToBinary() ([]byte, error) {
	var buffer bytes.Buffer
	var offsets struct {
		owner, group, sacl, dacl uint32
	}

	// Start with the fixed-size header
	// Revision (1 byte), Sbz1 (1 byte), Control (2 bytes)
	err := binary.Write(&buffer, binary.LittleEndian, uint8(1)) // Revision
	if err != nil {
		return nil, fmt.Errorf("failed to write revision: %v", err)
	}
	err = binary.Write(&buffer, binary.LittleEndian, uint8(0)) // Sbz1 (reserved)
	if err != nil {
		return nil, fmt.Errorf("failed to write sbz1: %v", err)
	}

	// Placeholder for Control flags (will be updated later)
	controlOffset := buffer.Len()
	err = binary.Write(&buffer, binary.LittleEndian, uint16(0))
	if err != nil {
		return nil, fmt.Errorf("failed to write control flags: %v", err)
	}

	// Placeholder for offsets
	offsetsOffset := buffer.Len()
	offsetStructure := make([]byte, 16) // 4 * 4-byte offsets
	buffer.Write(offsetStructure)

	// Convert and store SACL
	if sd.SystemAcl != nil {
		offsets.sacl = uint32(buffer.Len())
		saclBytes, err := marshalAcl(sd.SystemAcl)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SACL: %v", err)
		}
		buffer.Write(saclBytes)
	}

	// Convert and store DACL
	if sd.DiscretionaryAcl != nil {
		offsets.dacl = uint32(buffer.Len())
		daclBytes, err := marshalAcl(sd.DiscretionaryAcl)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal DACL: %v", err)
		}
		buffer.Write(daclBytes)
	}

	// Convert and store Owner SID
	if sd.Owner != "" {
		offsets.owner = uint32(buffer.Len())
		ownerSID, err := MarshalSidFromString(sd.Owner)
		if err != nil {
			return nil, fmt.Errorf("failed to parse owner SID: %v", err)
		}
		buffer.Write(ownerSID)
	}

	// Convert and store Group SID
	if sd.Group != "" {
		offsets.group = uint32(buffer.Len())
		groupSID, err := MarshalSidFromString(sd.Group)
		if err != nil {
			return nil, fmt.Errorf("failed to parse group SID: %v", err)
		}
		buffer.Write(groupSID)
	}

	// Update control flags
	controlFlags := sd.Control | SE_SELF_RELATIVE // Important: Set Self-Relative flag
	if sd.DiscretionaryAcl != nil {
		controlFlags |= SE_DACL_PRESENT
	}
	if sd.SystemAcl != nil {
		controlFlags |= SE_SACL_PRESENT
	}

	// Rewrite control flags
	controlBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(controlBytes, uint16(controlFlags))
	copy(buffer.Bytes()[controlOffset:controlOffset+2], controlBytes)

	// Update offsets
	offsetBytes := make([]byte, 4)
	if offsets.owner > 0 {
		binary.LittleEndian.PutUint32(offsetBytes, offsets.owner)
		copy(buffer.Bytes()[offsetsOffset:offsetsOffset+4], offsetBytes)
	}
	if offsets.group > 0 {
		binary.LittleEndian.PutUint32(offsetBytes, offsets.group)
		copy(buffer.Bytes()[offsetsOffset+4:offsetsOffset+8], offsetBytes)
	}
	if offsets.sacl > 0 {
		binary.LittleEndian.PutUint32(offsetBytes, offsets.sacl)
		copy(buffer.Bytes()[offsetsOffset+8:offsetsOffset+12], offsetBytes)
	}
	if offsets.dacl > 0 {
		binary.LittleEndian.PutUint32(offsetBytes, offsets.dacl)
		copy(buffer.Bytes()[offsetsOffset+12:offsetsOffset+16], offsetBytes)
	}

	return buffer.Bytes(), nil
}

func MarshalSidFromString(sidString string) ([]byte, error) {
	sidString = GetRawSid(sidString)
	if !strings.HasPrefix(sidString, "S-") {
		return nil, fmt.Errorf("invalid SID format")
	}

	// Basic SID parsing without Windows-specific dependencies
	parts := strings.Split(sidString, "-")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid SID format")
	}

	// Construct SID binary format
	var sidBytes []byte

	// SID Revision
	sidBytes = append(sidBytes, 1)

	// SubAuthority Count (derived from number of parts)
	sidBytes = append(sidBytes, uint8(len(parts)-3))

	// Parse and add Identifier Authority (last 6 bytes of first part)
	identifierAuthority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("invalid SID authority: %v", err)
	}
	for i := 5; i >= 0; i-- {
		sidBytes = append(sidBytes, uint8(identifierAuthority>>(i*8)))
	}

	// Parse and add Sub Authorities
	for _, subAuth := range parts[3:] {
		val, err := strconv.ParseUint(subAuth, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid sub-authority: %v", err)
		}
		valBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(valBytes, uint32(val))
		sidBytes = append(sidBytes, valBytes...)
	}

	return sidBytes, nil
}

// parseUint32 safely parses a string to uint32
func parseUint32(s string) (uint32, error) {
	var val uint32
	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		return 0, err
	}
	return val, nil
}

// marshalAcl converts an ACL struct to its binary representation
func marshalAcl(acl *Acl) ([]byte, error) {
	var buffer bytes.Buffer

	// ACL Header
	err := binary.Write(&buffer, binary.LittleEndian, uint8(acl.AclRevision)) // Revision
	if err != nil {
		return nil, fmt.Errorf("failed to write ACL revision: %v", err)
	}
	err = binary.Write(&buffer, binary.LittleEndian, uint8(0)) // Sbz1 (reserved)
	if err != nil {
		return nil, fmt.Errorf("failed to write ACL reserved byte: %v", err)
	}

	// Placeholder for ACL size
	sizeOffset := buffer.Len()
	err = binary.Write(&buffer, binary.LittleEndian, uint16(0))
	if err != nil {
		return nil, fmt.Errorf("failed to write ACL size: %v", err)
	}

	// Placeholder for ACE count
	aceCountOffset := buffer.Len()
	_ = aceCountOffset
	log.Printf("acl.Aces: %d: %+v", len(acl.Aces), acl.Aces)
	err = binary.Write(&buffer, binary.LittleEndian, uint16(len(acl.Aces)))
	if err != nil {
		return nil, fmt.Errorf("failed to write ACE count: %v", err)
	}

	// Sbz2
	err = binary.Write(&buffer, binary.LittleEndian, uint16(0))

	// Marshal ACEs
	for _, ace := range acl.Aces {
		if err := marshalAce(&buffer, ace); err != nil {
			return nil, fmt.Errorf("failed to marshal ACE: %v", err)
		}
	}

	// Update ACL size
	aclSize := buffer.Len()
	sizeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(sizeBytes, uint16(aclSize))
	copy(buffer.Bytes()[sizeOffset:sizeOffset+2], sizeBytes)

	return buffer.Bytes(), nil
}

// marshalAce converts an individual ACE to its binary representation
func marshalAce(buffer *bytes.Buffer, ace Ace) error {
	// Determine ACE flags
	var aceFlags uint8
	for _, flag := range ace.AceFlags {
		switch flag {
		case "OI":
			aceFlags |= OBJECT_INHERIT_ACE
		case "CI":
			aceFlags |= CONTAINER_INHERIT_ACE
		case "NP":
			aceFlags |= NO_PROPAGATE_INHERIT_ACE
		case "IO":
			aceFlags |= INHERIT_ONLY_ACE
		case "ID":
			aceFlags |= INHERITED_ACE
		}
	}

	// Convert SID to bytes
	sidBytes, err := MarshalSidFromString(ace.Sid)
	if err != nil {
		return fmt.Errorf("failed to convert SID: %v", err)
	}

	// Calculate ACE size
	aceSize := uint16(8 + len(sidBytes)) // Header + Mask + SID length

	// Write ACE header
	err = binary.Write(buffer, binary.LittleEndian, uint8(ace.AceType))
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, aceFlags)
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.LittleEndian, aceSize)
	if err != nil {
		return err
	}

	// Write access mask
	err = binary.Write(buffer, binary.LittleEndian, ace.AccessMask.Mask)
	if err != nil {
		return err
	}

	// Write SID
	buffer.Write(sidBytes)

	return nil
}
