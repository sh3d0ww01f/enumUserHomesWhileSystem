//go:build !windows
package enumUserHomesWhileSystem
func RevertToSelf() {}
func ImpersonateProcessToken(pid int32) error{}
func GetUserHomes() (map[string]string,map[string]int32, error) {}
