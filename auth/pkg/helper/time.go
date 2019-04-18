package helper

import (
	"strings"
	"time"
)

// CompareTimes - compare first passed time with second, in order to know - is first time bigger than second
// Time Format: "2006-01-02 15:04:05"
func CompareTimes(firstTime string, secondTime string) (bool, error) {
	parsedFirst, err := time.Parse(TimeFormat, firstTime)
	if err != nil {
		return false, err
	}
	parsedSecond, err := time.Parse(TimeFormat, secondTime)
	if err != nil {
		return false, err
	}

	diff := parsedFirst.Sub(parsedSecond)

	if (strings.HasPrefix(diff.String(), "-")) || (diff.String() == "0s") {
		return false, nil
	}
	return true, nil
}
