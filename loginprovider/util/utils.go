package util

import "crypto/sha1"

func Contains(stringSlice []string, contains string) bool {
	for _, element := range stringSlice {
		if element == contains {
			return true
		}
	}
	return false
}

// difference returns the elements in `a` that aren't in `b`.
func Difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

//remove removes toRemove from stringSlice and returns the index of the removed element and shrinked slice.
func removeOne(stringSlice []string, toRemove string) []string {
	index := -1
	for i, element := range stringSlice {
		if element == toRemove {
			index = i
		}
	}

	if index == -1 {
		return stringSlice
	}

	stringSlice[index] = stringSlice[len(stringSlice)-1]
	return stringSlice[:len(stringSlice)-1]
}

func SHA1Hash(cert []byte) ([]byte, error) {
	h := sha1.New()
	if _, err := h.Write(cert); err != nil {
		return nil, err
	}
	hash := h.Sum(nil)
	return hash, nil
}

//remove removes toRemove from stringSlice and returns the amount of removed elements
func Remove(stringSlice []string, toRemove ...string) []string {
	stringSliceCopy := make([]string, len(stringSlice))
	copy(stringSliceCopy, stringSlice)

	for _, element := range toRemove {
		stringSliceCopy = removeOne(stringSliceCopy, element)
	}

	return stringSliceCopy
}
