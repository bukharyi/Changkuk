package policyMgr

import (
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"os"
	"time"
	"github.com/bukharyi/policy2/util"
	//logb "github.com/Sirupsen/logrus"
	"reflect"
	"fmt"
)

//starts the scan daemon.
func scanDaemon() {
	for {//infinity loop
		time.Sleep(time.Duration(ChangkukConf.ScanPolicyInterval*1000) * time.Millisecond)
		//logb.Debugf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
		singleScan()
		standardizedPolicy()
	}
}
func singleScan() {
	//get all items in policyEnabledFolderPath
	files, err := getDirStructure(ChangkukConf.policyEnabledFolderPath)
	if err == false {
		logb.Fatalf("FATAL : cannot open %v",ChangkukConf.policyEnabledFolderPath)
	}

	//policiesSize:=len(Policies)
	//filesSize:=len(files)
	//logb.Infof("Policies=%v Files=%v,", policiesSize, filesSize)





	/*if equal:=reflect.DeepEqual(files, Policies); equal==false{

	}*/

	//remove policy if symlink is deleted.
	var policiesTemp []Policy
	var printFlag bool

	//check if the Policies slice is empty. if Empty skip this step.
	if Policies!=nil {
		for _, item := range Policies {
			for _, f := range files {
				if f.Name() == item.NAME {
					//logb.Debugf("FOUND %v", item.NAME)
					policiesTemp = append(policiesTemp, item)
				}
			}
		}

		if len(Policies)!=0&&len(Policies)!=len(files){
			printFlag=true
			logb.Infof("CHANGES in \"enable\" folder Policies=%v File=%v,", len(Policies), len(files))
			Policies=policiesTemp
			//print the items in the Policies slice.

		}
	}

	//for each item in the folder
	for _, f := range files {

		//the folderName is the policyName
		policyName := f.Name()
		symlinkPath := ChangkukConf.policyEnabledFolderPath + "/" + policyName

		//get the symlink file information
		symlinkFileInfo, err := os.Lstat(symlinkPath)
		if err != nil {
			logb.Errorf("%v - ERROR GETTING FILE INFO", symlinkPath)
			continue
		}

		//logb.Debugf("##DETECT POLICY=%v", symlinkFileInfo.Name())

		//VERIFICATION 1=check item in folder is symlink
		//if not symlink e.g. file or folder, delete it.
		if symlinkFileInfo.Mode() & os.ModeSymlink != os.ModeSymlink {
			logb.Errorf("(%v) - NOT A SYMLINK - deleting non symlink", f.Name())
			//TODO if INTEGRITY is true, then delete the file.
			if success := deleteFile(ChangkukConf.policyEnabledFolderPath + "/"+ f.Name()); success == true {
				logb.Infof("Deleted foreign item :- %v", f.Name())
			} else{
				logb.Errorf("Fail to delete foreign item :- %v", f.Name())
			}
			continue
		}

		//VERIFICATION 2=check if symlink is broken
		if symlinkExist, _ := exists(symlinkPath); symlinkExist == false {
			logb.Errorf("(%v) - SYMLINK BROKEN  - deleting symlink", symlinkFileInfo.Name())
			//TODO if INTEGRITY BOOLEAN is true, then delete the file.
			if success := deleteFile(ChangkukConf.policyEnabledFolderPath +"/"+ f.Name()); success == true {
				logb.Infof("Deleted bad symlink :- %v", f.Name())
			}
			//if previously loaded, then remove from memory.
			removePolicy(policyName)
			continue
		}

		yamlPath := symlinkPath + "/" + policyYamlName

		//VERIFICATION 3=check policy.yaml exist
		if yamlExist, _ := exists(yamlPath); yamlExist == false {
			logb.Errorf("(%v) - policy.yaml MISSING", policyName)
			removePolicyAndSymlink(policyName)
			continue
		}

		//push meta data of yaml file in POLICIES.
		//get last Modified, date created.
		yamlFileInfo, err := os.Lstat(yamlPath)

		if err != nil {
			logb.Errorf("(%v) - FAIL to get fileInfo", yamlPath)
			continue
		}

		var currPolicy Policy
		//parse the YAML file.
		parsedYAML, success := parseYAML(yamlPath)

		//var pURIArgs, pArgs, pCmd, pMetadata, pDesc string
		var pTrigger, pURIArgs, pArgs, pCmd string
		var pOnErrorAllow bool




		trigger := fmt.Sprintf("%v", reflect.TypeOf(parsedYAML["trigger"]))
		if (parsedYAML["trigger"] != nil) {
			if trigger != "string" {
				logb.Errorf("REMOVE/SKIP POLICY - <trigger> in policy.yaml should be string and not empty")
				removePolicyAndSymlink(policyName)

				continue
			}
			pTrigger = parsedYAML["trigger"].(string)
		}

		// this is to prevent "interface conversion: interface is nil, not string" error

		args := fmt.Sprintf("%v", reflect.TypeOf(parsedYAML["args"]))
		if (parsedYAML["args"] != nil) {
			if args != "string" {
				logb.Errorf("REMOVE/SKIP POLICY - <args> in policy.yaml should be string and not empty")
				removePolicyAndSymlink(policyName)

				continue
			}
			pArgs = parsedYAML["args"].(string)
		}

		// this is to prevent "interface conversion: interface is nil, not string" error

		uriargs := fmt.Sprintf("%v", reflect.TypeOf(parsedYAML["uriargs"]))
		if (parsedYAML["uriargs"] != nil) {
			if uriargs != "string" {
				logb.Errorf("REMOVE/SKIP POLICY - <uriargs> in policy.yaml should be string and not empty")
				removePolicyAndSymlink(policyName)

				continue
			}
			pURIArgs = parsedYAML["uriargs"].(string)
		}



		cmd:=fmt.Sprintf("%v",reflect.TypeOf(parsedYAML["cmd"]))
		if (parsedYAML["cmd"]!=nil) {
			if(cmd!="string"){
				logb.Errorf ("REMOVE SYMLINK/SKIP POLICY - <cmd> in policy.yaml should be string")
				removePolicyAndSymlink(policyName)

				continue
			}
			pCmd=parsedYAML["cmd"].(string)
		}


		// onerrorallow can be nil. but if set, it must be bool
		onerrorallow:=fmt.Sprintf("%v",reflect.TypeOf(parsedYAML["onerrorallow"]))
		if parsedYAML["onerrorallow"]!=nil {
			if(onerrorallow!="bool"){
				logb.Errorf ("REMOVE/SKIP POLICY - <onerrorallow> in policy.yaml should be bool")
				removePolicyAndSymlink(policyName)
				continue
			}
			pOnErrorAllow = parsedYAML["onerrorallow"].(bool)
		}

		metadata:=fmt.Sprintf("%v",reflect.TypeOf(parsedYAML["metadata"]))
		if (parsedYAML["metadata"]!=nil) {
			if(metadata!="string"){
				logb.Errorf ("REMOVE/SKIP POLICY - <metadata> in policy.yaml should be string")
				removePolicyAndSymlink(policyName)
				continue
			}
			//pMetadata=parsedYAML["metadata"].(string)
		}


		desc:=fmt.Sprintf("%v",reflect.TypeOf(parsedYAML["desc"]))
		if parsedYAML["desc"]!=nil {
			if(desc!="string"){
				logb.Errorf ("REMOVE/SKIP POLICY - <desc> in policy.yaml should be string")
				removePolicyAndSymlink(policyName)
				continue
			}
			//pDesc = parsedYAML["desc"].(string)
		}


		//VERIFICATION 4: CHECK the yaml can be parsed,
		//if policy previously loaded, remove from slice.
		if success == false {
			logb.Errorf("REMOVE/SKIP POLICY - failed to parse YAML")
			//fmt.Println(policyName)
			removePolicyAndSymlink(policyName)
			continue	//SKIP ADDING INTO POLICIES SLICE
		}

		//VERIFICATION 5: verify mandatory items.

		if (pCmd=="")||(pTrigger==""){
			logb.Errorf("REMOVE/SKIP POLICY - TRIGGER & CMD is mandatory field in policy.yaml")
			removePolicyAndSymlink(policyName)
			continue
		}

		//VERIFICATION 6: verify the yaml format BASED ON FORMAT
		if msg, success := verifyYAML(parsedYAML, policyKeyFmt); success == false {
			logb.Errorf("REMOVED/SKIP POLICY - policy.yaml Wrong format - %v", msg)
			removePolicyAndSymlink(policyName)
			continue	//SKIP ADDING INTO POLICIES SLICE
		}

		//VERIFICATION 7:verify the cmd path is valid inside YAML.
		if verify:=verifyCmdLink(symlinkPath+"/"+pCmd);verify==false{
			logb.Errorf("REMOVE/SKIP POLICY - %v not found",pCmd)
			removePolicyAndSymlink(policyName)
			continue	//SKIP ADDING INTO POLICIES SLICE
		}
		//TODO MASTERLOGGER OPEN THIS INCASE YOU GOT ERROR LOADING POLICY
		//logb.Debugf ("name=%v, \tcmd=%v, uriargs=%v, args=%v, onerrorallow=%v desc=%v, meta=%v" , policyName,  pCmd,pURIArgs, pArgs, pOnErrorAllow,pDesc,pMetadata)
		//load into Policies
		currPolicy = Policy{
			NAME:policyName,
			TRIGGER:pTrigger,
			ARGS:pArgs,
			URIARGS:pURIArgs,
			CMD:pCmd,
			ONERRORALLOW:pOnErrorAllow,
			YAMLINFO:YAMLINFO{
				FULLPATH: yamlPath,
				LASTMODIFIED:yamlFileInfo.ModTime(),
				ENABLE:true,
			},
		}

		if matched, index := contains( policyName); matched == true {

			//FORDEBUG logb.Debugf("Policy match at index %v", index)
			// if policy is newer replace it.
			if (currPolicy.LASTMODIFIED.Equal(Policies[index].LASTMODIFIED)) {
				//FORDEBUG logb.Debugf("LAST MOD SAME at index %v", index)
			} else {
				logb.Infof("Policy %v - changes detected. Updating in memory policies", policyName)
				//replace the old policy with new one.
				Policies = append(Policies[:index], currPolicy)
			}
		} else {
			Policies = append(Policies, currPolicy)
		}
	}

	if printFlag==true{

		//print the items in the Policies slice.
		for index, item := range Policies {
			logb.Infof("==POL%v=%v MODTIME=%v", index, item.NAME, item.LASTMODIFIED)
		}
	}

}
//remove a single policy from memory
func removePolicy (policyName string)(bool){
	if matched, index := contains(policyName); matched == true {
		var temp []Policy
		//FORDEBUG logb.Errorf("******************FOUND POLICY NEED TO REMOVE")
		//Append part before the removed element.
		// ... Three periods (ellipsis) are needed.
		temp = append(temp, Policies[0:index]...)
		// Append part after the removed element.
		temp = append(temp, Policies[index+1:]...)
		Policies = temp
		return true
	}
	return false
}


//check if the policy name matches in the slice.
func contains(policyName string) (bool, int) {
	for index, aSingleSlice := range Policies {
		//FORDEBUG logb.Errorf("--POLICY NAME - %v", aSingleSlice.NAME)
		if aSingleSlice.NAME == policyName {
			//FORDEBUG logb.Errorf("+++IN CONTAINS - FOUND POLICY=%v at INDEX=%v",aSingleSlice.NAME,index)
			return true, index
		}
	}
	//FORDEBUG logb.Errorf("+++IN CONTAINS - NOT FOUND ")
	return false, 0
}

// parse the YAML file.
// check if file exist and can be open.
// using yaml.Unmarshal it will check the correct variable type. e.g. bool, string, int, etc.
func parseYAML(YAMLPath string) (map[string]interface{}, bool){
	yamlFile, err := ioutil.ReadFile(YAMLPath)
	if err != nil {
		logb.Fatalf("%v file cannot be opened :-%v", YAMLPath, err)
	}

	var parsed map[string]interface{}

	err = yaml.Unmarshal(yamlFile, &parsed)
	if err != nil {
		logb.Errorf("failed to parse YAML file")
		return  parsed, false
	}
	return  parsed, true
}

//verify the cmdLink is available.
func verifyCmdLink(cmdPath string) (bool){
	if yamlExist, _ := exists(cmdPath); yamlExist == false {
		//if not exist return false
		return false
	}
	//if exist return true
	return true
}

//verify the format of YAML based on "format" sent.
func verifyYAML(yaml interface{}, format []string) (string, bool) {

	//type assertion
	yamlValue:=yaml.(map[string]interface{})
	var returnString string
	for yamlKey,_ := range yamlValue {

		for index, fmtValue :=range format {
			if yamlKey== fmtValue {
				break
			}
			if (index+1) == len(format){
				returnString=returnString + " "+ yamlKey
			}
		}
	}
	if(returnString!=""){
		return(returnString+" NOT FOUND"), false
	}
	return "",true
}

//check if the file/folder path exist
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil { return true, nil }
	if os.IsNotExist(err) { return false, nil }
	return true, err
}
//delete a single item in the path
func deleteFile(path string) bool {
	var err = os.Remove(path)
	if err!=nil{return false} else {return true}
}

//get the current dirStructure.
//It will not traverse subfolder
func getDirStructure(path string) ([]os.FileInfo, bool){
	if files, err := ioutil.ReadDir(path); err==nil{return files, true}
	return nil, false
}

func removePolicyAndSymlink(policyName string){
	removePolicy(policyName)
	if success := deleteFile(ChangkukConf.policyEnabledFolderPath +"/"+ policyName); success == true {
		logb.Infof("Successfully delete symlink  :- %v", policyName)
		moveFile(policyName,ChangkukConf.policyAvailableFolderPath,ChangkukConf.nonComplianceFolderPath )
	} else{
		logb.Errorf("Fail to delete symlink :- %v", policyName)
	}
}

func moveFile(file string, oldPath string, newPath string)  {
	oldPath=oldPath+"/"+file
	newPath=newPath+"/"+file
	logb.Infof("OLD=%v NEW%v", oldPath,newPath)
	var err = os.Rename(oldPath,newPath)
	if err==nil{
		logb.Infof("successfully move item  :- %v", file)

	} else {
		logb.Errorf("Fail to move item :- %v", file)
	}
}
