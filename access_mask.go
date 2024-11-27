package winsddlconverter

// Constants for access rights
const (
	DELETE                   = 0x00010000
	READ_CONTROL             = 0x00020000
	WRITE_DAC                = 0x00040000
	WRITE_OWNER              = 0x00080000
	SYNCHRONIZE              = 0x00100000
	STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
	FILE_ALL_ACCESS          = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF
	ACCESS_SYSTEM_SECURITY   = 0x01000000
	MAXIMUM_ALLOWED          = 0x02000000
	GENERIC_ALL              = 0x10000000
	GENERIC_EXECUTE          = 0x20000000
	GENERIC_WRITE            = 0x40000000
	GENERIC_READ             = 0x80000000
)

func ParseAccessMask(mask uint32) AccessMaskDetail {
	var flags []string

	maskCurrent := mask

	if maskCurrent&FILE_ALL_ACCESS == FILE_ALL_ACCESS {
		flags = append(flags, "FA")
		maskCurrent &= bitNot(FILE_ALL_ACCESS)
	} else {
		// Standard rights
		if maskCurrent&DELETE != 0 {
			flags = append(flags, "SD")
			maskCurrent &= bitNot(DELETE)
		}
		if maskCurrent&READ_CONTROL != 0 {
			flags = append(flags, "RC")
			maskCurrent &= bitNot(READ_CONTROL)
		}
		if maskCurrent&WRITE_DAC != 0 {
			flags = append(flags, "WD")
			maskCurrent &= bitNot(WRITE_DAC)
		}
		if maskCurrent&WRITE_OWNER != 0 {
			flags = append(flags, "WO")
			maskCurrent &= bitNot(WRITE_OWNER)
		}
		if maskCurrent&SYNCHRONIZE != 0 {
			flags = append(flags, "SY")
			maskCurrent &= bitNot(SYNCHRONIZE)
		}
	}

	if maskCurrent&GENERIC_EXECUTE != 0 {
		flags = append(flags, "GX")
		maskCurrent &= bitNot(GENERIC_EXECUTE)
	}
	if maskCurrent&GENERIC_WRITE != 0 {
		flags = append(flags, "GW")
		maskCurrent &= bitNot(GENERIC_WRITE)
	}
	if maskCurrent&GENERIC_READ != 0 {
		flags = append(flags, "GR")
		maskCurrent &= bitNot(GENERIC_READ)
	}
	if maskCurrent&GENERIC_ALL != 0 {
		flags = append(flags, "GA")
		maskCurrent &= bitNot(GENERIC_ALL)
	}

	// Special rights
	if maskCurrent&ACCESS_SYSTEM_SECURITY != 0 {
		flags = append(flags, "AS")
		maskCurrent &= bitNot(ACCESS_SYSTEM_SECURITY)
	}
	if maskCurrent&MAXIMUM_ALLOWED != 0 {
		flags = append(flags, "MA")
		maskCurrent &= bitNot(MAXIMUM_ALLOWED)
	}

	return AccessMaskDetail{
		Mask:       mask,
		Flags:      flags,
		HasUnknown: maskCurrent != 0,
	}
}

func EncodeAccessMask(detail *AccessMaskDetail) uint32 {
	var mask uint32
	if detail.HasUnknown {
		mask = detail.Mask
	}
	for _, flag := range detail.Flags {
		switch flag {
		case "FA":
			mask |= FILE_ALL_ACCESS
		case "SD":
			mask |= DELETE
		case "RC":
			mask |= READ_CONTROL
		case "WD":
			mask |= WRITE_DAC
		case "WO":
			mask |= WRITE_OWNER
		case "SY":
			mask |= SYNCHRONIZE
		case "GX":
			mask |= GENERIC_EXECUTE
		case "GW":
			mask |= GENERIC_WRITE
		case "GR":
			mask |= GENERIC_READ
		case "GA":
			mask |= GENERIC_ALL
		case "AS":
			mask |= ACCESS_SYSTEM_SECURITY
		case "MA":
			mask |= MAXIMUM_ALLOWED
		}
	}
	return mask
}

// ModToAccessMask posix permission (01, 02, 06) to AccessMask
func ModToAccessMask(input uint32) uint32 {
	var mask uint32

	execute := input&1 != 0
	write := input&2 != 0
	read := input&4 != 0

	if execute && write && read {
		mask = FILE_ALL_ACCESS
	} else {
		if execute {
			mask |= GENERIC_EXECUTE
		}
		if write {
			mask |= GENERIC_WRITE
		}
		if read {
			mask |= GENERIC_READ
		}
	}

	return mask
}
