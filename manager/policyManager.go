package policyMgr

import (

	"strings"
	"os"
	"regexp"
	"os/exec"
	"time"
	"bytes"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	//logb "github.com/Sirupsen/logrus"
	"github.com/Sirupsen/logrus"
	"github.com/bukharyi/policy2/util"
	"flag"

)

const configFilePath string = "../config/config.yml"

type ChangkukConfig struct {
	ScriptTimeout             int		`yaml:scripttimeout`
	DebugMode                 bool		`yaml:debugmode`
	ChangkukFolder            string		`yaml:changkukfolder`
	ScanPolicyInterval        int		`yaml:scanpolicyinterval`
	Integrity                 bool 		`yaml:integrity`
	policyEnabledFolderPath   string
	policyAvailableFolderPath string
	nonComplianceFolderPath   string
}
var ChangkukConf ChangkukConfig
var policyKeyFmt = []string {"trigger","uriargs","args", "cmd", "onerrorallow","desc", "metadata"}
//configKeyFmt:=[]string{"scripttimeout","debugmode","changkukfolder"}

const policyYamlName string = "policy.yaml"

type YAMLINFO struct {
	FULLPATH	string				//full path of policy.yaml
	LASTMODIFIED	time.Time			//last modified time of policy.yaml
	ENABLE         	bool   				//false=not enable  true=enable
}

type Policy struct {
	NAME         string				//MANDATORY - name of the trigger based on the folder name
	//TYPE         string `yaml:type`           	//action type dockeraction/container/event/others
	TRIGGER      string `yaml:trigger`        	//the actions/events/others e.g. container_create
	//SEQ 	     string `yaml:seq`			//MANDATORY - experiment feature to test pre or post.
	CMD          string `yaml:cmd`            	//MANDATORY - command to be executed by trigger
	URIARGS	     string `yaml:uriargs`		//OPTIONAL - args got from the URI.
	ARGS         string `yaml:args`           	//OPTIONAL - args pass to the cmd
	METADATA    string `yaml:metadata`		//OPTIONAL - provides the metadata of the policy.
							//	   - currently not included in the policies memory.
	DESC 	    string `yaml:desc`			//OPTIONAL - provides the desc of the policy.
							//	   - currently not included in the policies memory.
	ONERRORALLOW bool   `yaml:onerrowallow` 	//OPTIONAL - support error for TIMEOUT, ARGS, or CMD FAILURE.
						  	//false - very strict. Any failure on the script will void
						  	//true  - even if script fail, it will allow the command to proceed.
						  	//not defined - default false
	YAMLINFO

}

type dirStructure struct {
	fullPath 	string //fullpath of the directory
	theType		string //ENABLE or DISABLE. Other than that don't show
}




//declare a slice of policies
var Policies []Policy

func DisablePolicy(){
	//remove symlink
}
func EnablePolicy(){
	//create symlink
}
func ListPolicy(){
}

//OPTIONAL la
func InstallPolicy(){
}

//remove in available folder and rm symlink in enable folder
func UninstallPolicy(){
}

func InitLogger(){
	logb.Infof("STARTING Policy daemon")
	logb.Infof("CHANGKUKFOLDER:%v ",ChangkukConf.ChangkukFolder)
	logb.Infof("DEBUGMODE:%v ",ChangkukConf.DebugMode)
	logb.Infof("INTEGRITY:%v ",ChangkukConf.Integrity)
	logb.Infof("SCANPOLICYINTEVAL (S):%v ",ChangkukConf.ScanPolicyInterval)
	logb.Infof("GLOBAL SCRIPT TIMEOUT:%d",ChangkukConf.ScriptTimeout)

	scanDaemon()

}

func Init() {

	var success bool
	if success = loadConfig(); success == true {
		ChangkukConf.policyEnabledFolderPath = ChangkukConf.ChangkukFolder+"policies/enable"
		ChangkukConf.policyAvailableFolderPath = ChangkukConf.ChangkukFolder+"/policies/available"
		ChangkukConf.nonComplianceFolderPath = ChangkukConf.ChangkukFolder+"/policies/noncompliance"

	}

	logger()
//	loadTestPolicies()


}
func logger() {
	//setting the Flag information for app.

	var flagDebug = flag.Bool("debug", ChangkukConf.DebugMode ,"specifies the debug mode")

	flag.Parse() //parse the state logger
	if *flagDebug {
		logb.SetLogLevel(logrus.DebugLevel)
		logb.Infof("Plugin starts in : DEBUG level", )

	}else {
		logb.SetLogLevel(logrus.InfoLevel)
		logb.Infof("\"Plugin starts in : INFO level\"", )
	}

}


/*
func logger() {
	//setting the Flag information for app.

	var flagDebug = flag.Bool("debug", ChangkukConf.DebugMode ,"specifies the debug mode")


	flag.Parse() //parse the state logger


	path:="file.log"
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		logb.WithError(err).Errorf("error opening file: %s", path)
		logb.Fatal("%v",err)
	}
	logb.SetOutput(f)


	if *flagDebug {
		logb.SetLevel(logb.DebugLevel)
		logb.Infof("Plugin starts in : DEBUG level")

	}else {
		logb.SetLevel(logb.InfoLevel)
		logb.Infof("\"Plugin starts in : INFO level\"")
	}

}
*/

func loadConfig()(bool){

	yamlFile, err := ioutil.ReadFile(configFilePath)

	if err != nil {
		logb.Fatalf("%v file cannot be opened :-%v", configFilePath,err)
	}

	if err = yaml.Unmarshal(yamlFile, &ChangkukConf);err != nil {
		logb.Fatalf("Unable to parse config.yml")
		return false
	}
return true
}







//check if policy is AVAILABLE or ENABLED.
// 1. NOT-AVAILABLE - policy is not in "AVAILABLE"folder.
// 2. NOT-ENABLED   - script is in "AVAILBLE" folder, but no symlink in "ENABLE" folder
// 3. AVAIL-ENABLED - policy is available & enabled properly.
func isEnabledPolicy(policyName string) (returnStatus bool, response string){

	policyEnabledPath:= ChangkukConf.policyEnabledFolderPath +"/"+policyName+"/"
	policyAvailablePath:= ChangkukConf.policyAvailableFolderPath +"/"+policyName+"/"

	//check the policy is AVAILABLE in the path?
	if _, err := os.Stat(policyAvailablePath); err==nil{

		//check the policy is ENABLE in the path?
		if _, err := os.Stat(policyEnabledPath); err==nil {
			response ="AVAIL-ENABLED"
			return true, response
		}else{
			response ="NOT-ENABLED"
			return false, response
		}
	}
	response ="NOT-AVAILABLE"
	return false, response
}
//Execute script in pluginpath
//policy = a single Policy
//cmdType = EVAL_CMD or ACTION_CMD
//returnInfo = string of messages, and status
func ExecuteCommand(policyName string, cmdStr string,uriArgsStr string, argsStr string) ( string,  bool) {

	response := " CMD=("+ cmdStr + ") URIARGS ("+uriArgsStr+") ARGS=("+ argsStr +")"

	//logb.Debugf("###################SCRIPT(RUN):-%s", response)

	var fullArgs string
	if uriArgsStr!="" && argsStr!=""{
		//TODO TEST SEMICOLON
		fullArgs=uriArgsStr +";"+argsStr
		//fullArgs=uriArgsStr +","+argsStr
	}
	if uriArgsStr!="" && argsStr==""{
		fullArgs=uriArgsStr
	}
	if uriArgsStr=="" && argsStr!=""{
		fullArgs=argsStr
	}

	var argsArray []string
	if (fullArgs !=""){
		//fmt.Println("\n\n###",fullArgs,"\n\n")
		//TODO TEST SEMICOLON
		re := regexp.MustCompile(`;`)
		//split the args by , and into slice
		result := re.Split(fullArgs, -1)
		//remove the key and get the value only

		//var result3 []string
		for _,pair:=range result{

			//fmt.Println("THEPAIR:=",pair)
			re2:=regexp.MustCompile(`:(\".+?\")$`)

			result2:=re2.FindStringSubmatch(pair)
			if(len(result2)>0){
			//fmt.Println("RESULT2:=",result2[1])
			//	spew.Dump(result2)


				/*
			//re2:=regexp.MustCompile(`(.+?):\"(.+?)\"`)
			re2:=regexp.MustCompile(`.+?:\".+?\"`)
			result2:=re2.Split(pair,-1)

			spew.Dump(result2)
			result3= result2[1:len(result2)]
			fmt.Println("RESULT3:=",result3)
			spew.Dump(result3)
			*/
				//remove back the backslash
				result2[1]=strings.TrimRight(result2[1],`"`)
				result2[1]=strings.TrimLeft(result2[1],`"`)
			argsArray =append(argsArray,result2[1])
			}

			//spew.Dump(argsArray)
			//fmt.Println(result3)
		}
	}
	cmdPath := ChangkukConf.policyEnabledFolderPath +"/"+policyName+"/"+ cmdStr


	//check the policy is enable & available in the path?
	enable, response :=isEnabledPolicy(policyName)

	if  enable==true && response =="AVAIL-ENABLED" {
		//fmt.Print("ARGSARRAY:")
		//spew.Dump(argsArray)
		//fmt.Println("")
		cmd := exec.Command(cmdPath, argsArray...)
		//fmt.Print("CMD:")
		//spew.Dump(cmd)
		//fmt.Println("")
		var cmdStdout bytes.Buffer
		cmd.Stdout = &cmdStdout

		if err := cmd.Start(); err != nil{
			logb.Debugf("SCRIPT(ERR)  :- \"%s %s\"",cmdPath, strings.Join(argsArray, " "))
			logb.Debugf("SCRIPT(ERR)  :- ERR:%s STDOUT:(%s)", err, cmdStdout.String())


			return "SCRIPT-FAIL",false
		}

		done:=make(chan error, 1)
		go func(){
			done <- cmd.Wait()
		}()
		select {
		case <-time.After(time.Duration(ChangkukConf.ScriptTimeout) * time.Second):
			if err:= cmd.Process.Kill(); err!= nil {
				logb.Errorf("failed to kill PROCESS=%s ERR=(%s)",cmdPath, err)
			}
			logb.Errorf("SCRIPT(ERR) :- PROCESS=(%s) killed as TIMEOUT=%v seconds reached",cmdPath, ChangkukConf.ScriptTimeout)

		case err := <-done:
			if err != nil {
				logb.Errorf("SCRIPT(ERR) :- ERR=%v", err)
			} else {
				response:=" CMD=("+ cmdStr +" "+strings.Join(argsArray, " ")+") RETURN_MSG=("+strings.TrimSpace(cmdStdout.String())+")"
				logb.Debugf("SCRIPT(OK) :-%s ",response)

				return cmdStdout.String(),true
			}

		}

	//policy not enabled, but available
	}else if (enable==false && response =="NOT-ENABLED"){

		logb.Debugf("SCRIPT(NOT-ENABLED)  :-\"%s %s\"",cmdPath, strings.Join(argsArray, " "))
		return response,false

	//policy not enabled, but available
	}else if (enable==false && response =="NOT-AVAILABLE"){

		logb.Debugf("SCRIPT(NOT-AVAILABLE)  :-\"%s %s\"",cmdPath, strings.Join(argsArray, " "))
		return response,false
	}
	return "ACHTUNG!!! THIS IS NOT SUPPOSED TO HAPPENED", false
}
//standardize the policy int small letters.
func standardizedPolicy(){
	for index := range Policies {
		Policies[index].NAME =strings.ToLower(Policies[index].NAME)
		//Policies[index].TYPE =strings.ToLower(Policies[index].TYPE)
		//Policies[index].TRIGGER =strings.ToLower(Policies[index].TRIGGER)
		Policies[index].ARGS=strings.ToLower(Policies[index].ARGS)
		Policies[index].CMD=strings.ToLower(Policies[index].CMD)

	}
}
//get policies that matched the TRIGGERS.
func GetPolicies(TRIGGER string) (policies []Policy) {

	//to be safe lower all parameters
	TRIGGER=strings.ToLower(TRIGGER)

	for index := range Policies {
		if(Policies[index].TRIGGER ==TRIGGER ) {
			policies = append(policies, Policies[index])
		}

	}
	return policies
}