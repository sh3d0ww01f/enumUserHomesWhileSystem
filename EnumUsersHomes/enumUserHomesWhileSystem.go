package enumUserHomesWhileSystem
import (
	"syscall"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

var (
	users                        = make(map[string]bool)
	userPids                     = make(map[string]int32)
	userHomes                    = make(map[string]string)
	modkernel32 *windows.LazyDLL = windows.NewLazySystemDLL("kernel32.dll")
	modadvapi32 *windows.LazyDLL = windows.NewLazySystemDLL("advapi32.dll")
	modshell32  *windows.LazyDLL = windows.NewLazySystemDLL("shell32.dll")

	procOpenProcess             *windows.LazyProc = modkernel32.NewProc("OpenProcess")
	procOpenProcessToken        *windows.LazyProc = modadvapi32.NewProc("OpenProcessToken")
	procDuplocateTokenEx        *windows.LazyProc = modadvapi32.NewProc("DuplicateTokenEx")
	procSetThreadToken          *windows.LazyProc = modadvapi32.NewProc("SetThreadToken")
	procRevertToSelf            *windows.LazyProc = modadvapi32.NewProc("RevertToSelf")
	procImpersonateLoggedOnUser *windows.LazyProc = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	procGetUserNameW            *windows.LazyProc = modadvapi32.NewProc("GetUserNameW")
	procSHGetFolderPathW        *windows.LazyProc = modshell32.NewProc("SHGetFolderPathW")
)

// ProcessAccessFlags
const (
	All                          uint32 = 0x001F0FFF
	Terminate                    uint32 = 0x00000001
	CreateThread                 uint32 = 0x00000002
	VirtualMemoryOperation       uint32 = 0x00000008
	VirtualMemoryRead            uint32 = 0x00000010
	VirtualMemoryWrite           uint32 = 0x00000020
	DuplicateHandle              uint32 = 0x00000040
	CreateProcess                uint32 = 0x000000080
	SetQuota                     uint32 = 0x00000100
	SetInformation               uint32 = 0x00000200
	QueryInformation             uint32 = 0x00000400
	QueryLimitedInformation      uint32 = 0x00001000
	Synchronize                  uint32 = 0x00100000
	TOKEN_IMPERSONATE            uint32 = 0x00000004
	TOKEN_DUPLICATE              uint32 = 0x00000002
	SECURITY_IMPERSONATION_LEVEL int    = 2
	CSIDL_PROFILE                       = 0x28
)
func RevertToSelf() {
	procRevertToSelf.Call()
}
func getCurrentUser() (string, error) {
	usernameBuf := make([]uint16, 256)
	var size uint32 = uint32(len(usernameBuf))
	ret, _, err := procGetUserNameW.Call(uintptr(unsafe.Pointer(&usernameBuf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		//fmt.Printf("Failed to get current username. err:%s\n", err)
		return "", err
	}

	username := syscall.UTF16ToString(usernameBuf[:size-1])
	//fmt.Printf("[+] Impersonateto %s[Current user:%s]\n", username, username)
	return username, nil
}
func getUserHome() (string, error) {
	CSIDL_OPTION := CSIDL_PROFILE
	var path [syscall.MAX_PATH]uint16
	ret, _, err := procSHGetFolderPathW.Call(0, uintptr(CSIDL_OPTION), 0, 0, uintptr(unsafe.Pointer(&path[0])))
	path_ := syscall.UTF16ToString(path[:])
	if ret != 0 {
		//fmt.Printf("%s", path_)
		return "", err
	}
	return path_, nil
	//fmt.Printf("%s", path_)
}
func getUserName(pid int32) (string, error) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return "", err
	}
	username, err := p.Username()
	if err != nil {
		return "", err
	}
	return username, nil
}

// OpenProcess ->  OpenProcessToken -> DuplocateToken -> SetThreadToken
func ImpersonateProcessToken(pid int32) error {
	//OpenProcess
	//打开进程
	desiredAccess := QueryInformation
	inheritHandle := 1
	hProcess, _, err := procOpenProcess.Call(uintptr(desiredAccess), uintptr(inheritHandle), uintptr(pid))
	if hProcess != 0 {
		//	fmt.Printf("[+] successfully:%s [OpenProcess]\n", err)
	} else {
		//fmt.Printf("[-] error:%s [OpenProcess]\n", err)
		return err
		//	return err
	}

	//OpenProcessToken
	//进一步打开token
	desiredAccess = TOKEN_IMPERSONATE | TOKEN_DUPLICATE
	var hToken uintptr

	statusCode, _, err := procOpenProcessToken.Call(hProcess, uintptr(desiredAccess), uintptr(unsafe.Pointer(&hToken)))
	if statusCode == 0 {
		//	fmt.Printf("[-] error:%s [OpenProcessToken]\n", err)
		return err
	} else {
		//	fmt.Printf("[+] successfully:%s [OpenProcessToken]\n", err)
	}
	//DuplocateToken
	//开始复制token
	var DuplicatedToken uintptr
	impersonationLevel := SECURITY_IMPERSONATION_LEVEL
	desiredAccess = TOKEN_IMPERSONATE
	statusCode, _, err = procDuplocateTokenEx.Call(hToken, uintptr(desiredAccess), 0, uintptr(impersonationLevel), uintptr(impersonationLevel), uintptr(unsafe.Pointer(&DuplicatedToken)))
	if statusCode == 0 {
		//	fmt.Printf("[-] error:%s [DuplicateTokenEx]\n", err)
		return err
	} else {
		//	fmt.Printf("[+] successfully:%s [DuplicateTokenEx]\n", err)
	}
	//SetThreadToken
	//设置token
	statusCode, _, err = procSetThreadToken.Call(0, DuplicatedToken)
	if statusCode == 0 {
		//	fmt.Printf("[-] error:%s [procSetThreadToken]\n", err)
		return err
	} else {
		//fmt.Printf("[+] successfully:%s [procSetThreadToken]\n", err)
	}

	return nil
}
// GetUserHomes() returns 用户|用户home 用户|explorer's pid ，err
func GetUserHomes() (map[string]string,map[string]string, error) {
	
	// 获取所有进程列表
	processes, err := process.Processes()
	if err != nil {
		//fmt.Println("[-] Failed to get processesList:", err)
		return nil, nil, err
	}
	// 遍历进程列表
	for _, p := range processes {
		// 获取进程ID和进程名称
		processPid := p.Pid
		processName, _ := p.Name()
		username, _ := getUserName(processPid)

		if processName == "explorer.exe" {
			if users[username] != true {
				//fmt.Printf("[PID:%d][Username:%s][Name:%s]\n", processPid, username, processName)
				users[username] = true
				//变更权限
				err = ImpersonateProcessToken(processPid)
				if err != nil {
					//fmt.Printf("[-] ImpersonateProcessToken Failed:%s\n", err)
					return nil, nil ,err
				}
				//fmt.Printf("The user now is :%s\n", string(currentUser.Username))
				//fmt.Printf("%s %s", currentUser.Username, err)
				currentUsername, err := getCurrentUser()
				userHome, err := getUserHome()
				userHomes[currentUsername] = userHome
				userPids[currentUsername] = processPid
				if err != nil {
					//fmt.Printf("[-] Get UserHome error:%s", err)
					return nil, nil ,err
				} else {
					//	fmt.Printf("[+] Get UserHome success[userhome:%s]\n", userHome)
				}

				//回退权限
				RevertToSelf() 
			} else {
				//该用户已经获取过了
				//fmt.Print("[-] The user is signed ")
			}
		}

	}
	return userHomes, userPids, nil
}
