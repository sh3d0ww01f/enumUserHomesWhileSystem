//go:build !windows
package enumUserHomesWhileSystem
func RevertToSelf() {}
func ImpersonateProcessToken(pid int32) error{return nil}
func GetUserHomes() (map[string]string,map[string]int32, error) {return nil,nil,nil}
