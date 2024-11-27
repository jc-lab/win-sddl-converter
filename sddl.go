package winsddlconverter

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var sddlAclPattern = regexp.MustCompile("^(D:|S:)(\\w*)((?:\\([^)]+\\))+)")
var sddlControlFlagsPattern = regexp.MustCompile("^(P|AI)")

func ParseSDDL(sddl string) (*SecurityDescriptor, error) {
	var err error

	sd := &SecurityDescriptor{}

	sr := &stringReader{s: sddl}
	for sr.Len() > 0 {
		c := sr.ReadChars(2)
		switch c {
		case "O:":
			sd.Owner, err = sr.ReadSid()
			if err != nil {
				return nil, err
			}
		case "G:":
			sd.Group, err = sr.ReadSid()
			if err != nil {
				return nil, err
			}
		default:
			remaining := c + sr.Remaining()
			matches := sddlAclPattern.FindStringSubmatchIndex(remaining)
			if len(matches) == 0 {
				return nil, errors.New("acl parse failed: " + sr.Remaining())
			}
			sr.Consume(matches[1] - 2)

			// (D:|S:)(\\w*)(\\([^)]+\\))+"
			first := remaining[matches[2]:matches[3]]
			controlFlags, err := parseControlStringsFromSDDL(remaining[matches[4]:matches[5]])
			if err != nil {
				return nil, err
			}
			body := remaining[matches[6]:matches[7]]

			acl, err := parseAclFromSDDL(body)
			if err != nil {
				return nil, err
			}

			if first == "D:" {
				for _, flag := range controlFlags {
					switch flag {
					case "P":
						sd.Control |= SE_DACL_PROTECTED
					case "AI":
						sd.Control |= SE_DACL_AUTO_INHERITED
					}
				}
				sd.DiscretionaryAcl = acl
			} else if first == "S:" {
				for _, flag := range controlFlags {
					switch flag {
					case "P":
						sd.Control |= SE_SACL_PROTECTED
					case "AI":
						sd.Control |= SE_SACL_AUTO_INHERITED
					}
				}
				sd.SystemAcl = acl
			} else {
				return nil, errors.New("acl parse failed: invalid prefix: '" + first + "'")
			}
		}
	}
	
	return sd, nil
}

func parseControlStringsFromSDDL(input string) ([]string, error) {
	var flags []string
	for len(input) > 0 {
		matches := sddlControlFlagsPattern.FindStringSubmatchIndex(input)
		if len(matches) == 0 {
			return nil, errors.New("unknown control flag: " + input)
		}
		flag := input[matches[2]:matches[3]]
		flags = append(flags, flag)
		input = input[matches[1]:]
	}
	return flags, nil
}

func parseAclFromSDDL(aclString string) (*Acl, error) {
	acl := &Acl{AclRevision: 2, Aces: []Ace{}}

	// Check for ACL flags
	parts := strings.SplitN(aclString, "(", 2)
	if len(parts) > 1 {
		// TODO: Parse ACL flags if needed
		aclString = parts[1]
	}

	aceStrings := strings.Split(aclString, "(")
	for _, aceString := range aceStrings {
		if aceString == "" {
			continue
		}
		ace, err := parseAceFromSDDL(aceString)
		if err != nil {
			return nil, fmt.Errorf("error parsing ACE: %v", err)
		}
		acl.Aces = append(acl.Aces, *ace)
	}

	return acl, nil
}

func parseAceFromSDDL(aceString string) (*Ace, error) {
	var err error

	aceString = strings.Trim(aceString, "()")
	parts := strings.Split(aceString, ";")
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid ACE format: not enough components: " + aceString)
	}

	ace := &Ace{}

	ace.AceType, err = ParseAceType(parts[0])
	if err != nil {
		return nil, err
	}

	ace.AceFlags = parseAceFlagsFromSDDL(parts[1])
	accessMask, err := parseAccessMaskFromSDDL(parts[2])
	if err != nil {
		return nil, fmt.Errorf("error parsing access mask: %v", err)
	}
	ace.AccessMask = accessMask
	ace.Sid = parts[5]

	return ace, nil
}

func parseAceFlagsFromSDDL(flagsString string) []string {
	var flags []string
	for i := 0; i < len(flagsString); i += 2 {
		flags = append(flags, flagsString[i:i+2])
	}
	return flags
}

func parseAccessMaskFromSDDL(maskString string) (AccessMaskDetail, error) {
	if strings.HasPrefix(maskString, "0x") {
		mask, err := strconv.ParseUint(maskString[2:], 16, 32)
		if err != nil {
			return AccessMaskDetail{}, fmt.Errorf("invalid hexadecimal access mask: %v", err)
		}
		return ParseAccessMask(uint32(mask)), nil
	}

	var flags []string
	for i := 0; i < len(maskString); i += 2 {
		if i+2 <= len(maskString) {
			flags = append(flags, maskString[i:i+2])
		}
	}

	detail := AccessMaskDetail{
		Flags:      flags,
		HasUnknown: false,
	}
	detail.Mask = EncodeAccessMask(&detail)
	return detail, nil
}
