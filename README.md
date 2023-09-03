# enumUserHomesWhileSystem
enumUserHomesWhileSystem by Go
## Doc
### How to use?? 
#### GetUserHomes()   returns map[string]string,map[string]pid,error
To enum the users'home&the (Pid of different "explorer.exe")  in the computer
```
package main
import (
	"fmt"
	enumUserHomesWhileSystem "github.com/sh3d0ww01f/enumUserHomesWhileSystem/EnumUsersHomes"
)

func main() {
	usernameAndUserHome, usernameAndPid, _ := enumUserHomesWhileSystem.GetUserHomes()
	for username, userHome := range usernameAndUserHome {
		fmt.Printf("[username:%s][userhome:%s][PID:%d]\n", username, userHome, usernameAndPid[username])
	}
}

```

The output is following:
```
C:\Users\oagi\Desktop>main
[username:oagi][userhome:C:\Users\oagi][PID:1968]
[username:Administrator][userhome:C:\Users\Administrator][PID:2888]
```
#### ImpersonateProcessToken(processPid) returns bool
To impersonate other users' process
#### RevertToSelf() 
This is match with ImpersonateProcessToken
