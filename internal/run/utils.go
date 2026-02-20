package run

import "strings"

func BootArgsPrepare(args ...string) string {
	var sb strings.Builder
	for _, arg := range args {
		if strings.Count(arg, "'") != strings.Count(arg, "\\'") {
			sb.WriteByte('"')
			sb.Write([]byte(arg))
			sb.WriteByte('"')
			sb.WriteByte(' ')
		} else {
			sb.Write([]byte(arg))
			sb.WriteByte(' ')
		}
	}

	return sb.String()
}
