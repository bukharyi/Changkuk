package actions

import(
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/docker/engine-api/client"
	"github.com/bukharyi/policy2/manager"
	"strings"
	"github.com/bukharyi/policy2/util"
	//logb "github.com/Sirupsen/logrus"
	//"fmt"
	"regexp"
	//"fmt"
	"net/url"
	"encoding/json"
	"strconv"
	"time"
	"os"

	//"fmt"
	"fmt"
	"github.com/davecgh/go-spew/spew"
)

type ActionRegularExpression struct{
	action 	    string
	actionRE    string

}
//TODO
var myTime,startTime,stopTime string

var DockerActionRE = []ActionRegularExpression {
	{action:"container", actionRE:`^container`},
	{action:"image", actionRE:`^image`},
	{action:"volume", actionRE:`^volume`},
	{action:"network", actionRE:`^network`},
	{action:"docker", actionRE:`^docker`},
}

type UriRegularExpressionSet struct{
	excludedActions []string
	actionTypeRE    string
	actionIdRE      string
}


//type container, volume, network, docker for docker API version 1.2.1
var URIs =map[string]UriRegularExpressionSet{
	"container":{
		actionTypeRE:`^container`,
		actionIdRE:`(?:\/containers\/(\w+)\/)|(?:\/containers\/(\w+)\?)|(?:\/exec\/(\w+))`,
		excludedActions:[]string{"container_list", "container_commit", "container_create"},
	}, "image":{
		actionTypeRE:`^image`,
		actionIdRE:`(?:\/images\/(\w+)\/)|(?:\/images\/(\w+))|(?:\/images\/(\w+)\/json\/)`,
		excludedActions:[]string{"images_archive","images_search","image_create","images_load","image_build","image_list"},
	}, "volume":{
		actionTypeRE:`^volume`,
		actionIdRE:`(?:\/volumes\/(\w+))`,
		excludedActions:[]string{"volume_list","volume_create"},
	}, "network":{
		actionTypeRE:`^network`,
		actionIdRE:`(?:\/networks\/(\w+)\/)|(?:\/networks\/(\w+)\?)|(?:\/networks\/(\w+))`,
		excludedActions:[]string{"network_list","network_create"},
	}, "docker":{
		actionTypeRE:`^docker`,
		actionIdRE:``,
		excludedActions:[]string{"docker_events","docker_version","docker_auth","docker_ping","docker_info"},
	},
}



type changkukPolicy struct{
	changkukPolicyClient *client.Client
}

type PluginConfig struct{
	DockerHost string
	DockerApiVer string
	EngineApiCli string
	AgentName string
	PluginSocket string
}

func getTimeStamp()(string){
	timestampNano := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	return timestampNano
}

//func logOutput(d1 string){

func logOutput(d1 string){

	 //d1 = startTime+", "+stopTime+"\n"

	f, err := os.OpenFile("output.txt", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.WriteString(d1); err != nil {
		panic(err)
	}



}

//initialize AuthzPlugin
func Init(config PluginConfig){
	//folder structure is already checked by go-plugin-helper
	plugin, err := initPlugin(config)
	if err != nil {
		logb.Fatal(err)
	}
	handler:=authorization.NewHandler(plugin)

	err2:=handler.ServeUnix("root",config.PluginSocket)
	if err2 != nil {
		logb.Fatalf("error ",err)
	}
}
//initialize the Changkuk Policy pluginClient
func initPlugin(config PluginConfig) (*changkukPolicy, error){

	headers :=map[string]string{config.AgentName:config.EngineApiCli}
	logb.Infof("STARTING Plugin daemon")
	logb.Infof("DOCKERHOST:%s ",config.DockerHost)
	logb.Infof("DOCKERAPIVER:%s", config.DockerApiVer)
	logb.Infof("AGENT:%s",config.AgentName,)
	logb.Infof("ENGINE CLI:%s",config.EngineApiCli)


	c, err:= client.NewClient(config.DockerHost,config.DockerApiVer,nil,headers)

	if err != nil {
		return nil, err
	}//end if
	return &changkukPolicy{changkukPolicyClient:c},nil
}




func getActionType(TRIGGER string) (actionType string){
	if TRIGGER ==""{
		logb.Errorf("Empty TRIGGER type")
		return ""
	}else{
		//interate the URI. If the TRIGGER  matched with action, return the action.
		for action, uri := range URIs{
			re:=regexp.MustCompile(uri.actionTypeRE)

			if(len(re.FindStringSubmatch(TRIGGER))>0){
				return action
			}
		}

	}
	return ""
}

//check URI Args is empty
//URIARGS = the value of action_ARGS or eval_ARGS
//REQ  = the request body
func checkURIArgs(TRIGGER string, URIARGS string, REQ authorization.Request)( bool, string) {

	//get the actiontype first.
	actionType:=getActionType(TRIGGER)
	if actionType==""{
		logb.Errorf("ERROR in getting ActionType")
		return false, ""
	}

	var commandURIArgs string
	//parse the requestURI using parseRequestURI
	if(URIARGS!=""){
		//parse requestBody
		if _, commandURIArgs = parseRequestURI(actionType,REQ, URIARGS); commandURIArgs == "" {
			return false, ""
		} else {
			return true, commandURIArgs
		}
	}

	return true, ""

}


//check if the Args is empty
//ARGS = the value of action_ARGS or eval_ARGS
//REQ  = the request body
func checkArgs(ARGS string, REQ authorization.Request)( bool, string){


	var commandArgs string
	if (ARGS != "") {
		//parse requestBody
		if _, commandArgs = parseRequestBody(REQ, ARGS); commandArgs == "" {
			return false, ""
		} else {
			return true, commandArgs
		}
	}
	//commandArgs is empty.
	return true, ""
}




func (p *changkukPolicy) AuthZReq(req authorization.Request) authorization.Response {

	startTime=getTimeStamp()
	//logOutput("start, "+startTime+"\n")

	//the populated response msg
	var finalResponseMsg string = "SUMMARY:-"
	var response string
	//get current docker action
	onTrigger := ParseRoute(req.RequestMethod, req.RequestURI)

	//get policies that match the docker action trigger e.g. container_create, container_start, etc.
	//the 1 TRIGGER = POLICYNAME
	matchedPolicies := policyMgr.GetPolicies(onTrigger)

	//spew.Dump(req.RequestURI)

	logb.Infof(fmt.Sprintf("TRIGGER=%s, URI(%v)=%v, MATCHED=%d", onTrigger,req.RequestMethod,req.RequestURI, len(matchedPolicies)))

	//check total policies
	switch{
	//if length == 0, skip
	case len(matchedPolicies) == 0:
		return authorization.Response{Allow:true}

	//if length more than 1, display error and just get the first policy to process.
	case len(matchedPolicies) > 1 :
		response="only one policy per trigger, taking the first policy instead."
		logb.Errorf(response)
	}

	//get the first policy only.
	policyName := matchedPolicies[0].NAME
	policyTrigger:= matchedPolicies[0].TRIGGER
	policyArgs := matchedPolicies[0].ARGS
	policyURIArgs := matchedPolicies[0].URIARGS
	policyCmd := matchedPolicies[0].CMD
	policyOnErrorAllow := matchedPolicies[0].ONERRORALLOW

	//for logging purposes
	var onErrorAllowStr  string
	if(policyOnErrorAllow==true){onErrorAllowStr="(ALLOWED)"}else {onErrorAllowStr="(BLOCKED)" }


	logb.Info("POLICY("+policyName+"):- processing")


	//process the PolicyURIArgs
	var commandURIArgs string = ""

	if policyURIArgs!=""{
		response="POLICY("+policyName+"):- processing URIARGS=("+policyURIArgs+")"
		logb.Debugf(response)
		if ok, URIargs := checkURIArgs(policyTrigger ,policyURIArgs, req); ok == true {
			commandURIArgs=URIargs
			response="POLICY("+policyName+"):- processed  URIARGS=("+URIargs+")"
			logb.Debugf(response)
		} else{
			response="POLICY("+policyName+"):- Unable to parse URIARGS="+policyURIArgs
			logb.Error(response)

			response=fmt.Sprintf("POLICY(%s):- is %s FLAG onerrorallow=%v" ,policyName,onErrorAllowStr ,policyOnErrorAllow)
			logb.Errorf(response)

			finalResponseMsg = finalResponseMsg + response
			return authorization.Response{
				Allow:policyOnErrorAllow,
				Msg:finalResponseMsg,
			}
		}
	}else{
		response="POLICY("+policyName+"):- No URIARGS"
		logb.Debugf(response)
	}


	//process the PolicyArgs
	var commandArgs string = ""

	if policyArgs!=""{
		response="POLICY("+policyName+"):- processing ARGS=("+policyArgs+")"
		logb.Debugf(response)
		if ok, args := checkArgs(policyArgs, req); ok == true {
			commandArgs=args
			response="POLICY("+policyName+"):- processed  ARGS=("+args+")"
			fmt.Println("")
			logb.Debugf(response)
		} else{
			response="POLICY("+policyName+"):- Unable to parse ARGS="+policyArgs
			logb.Error(response)

			response=fmt.Sprintf("POLICY(%s):- is %s FLAG onerrorallow=%v" ,policyName,onErrorAllowStr ,policyOnErrorAllow)
			logb.Errorf(response)

			finalResponseMsg = finalResponseMsg + response
			return authorization.Response{
				Allow:policyOnErrorAllow,
				Msg:finalResponseMsg,
			}
		}
	}else{
		response="POLICY("+policyName+"):- No ARGS"
		logb.Debugf(response)
	}



	//process the PolicyCmd

	msg, cmdSuccess := policyMgr.ExecuteCommand(
		policyName,
		policyCmd,
		commandURIArgs,
		commandArgs)

	if(msg==""){

		response="POLICY("+policyName+"):- script must return valid msg"
		finalResponseMsg=finalResponseMsg + response
		logb.Errorf(response)

		response=fmt.Sprintf("POLICY(%s):- is %s FLAG onerrorallow=%v" ,policyName,onErrorAllowStr ,policyOnErrorAllow)
		logb.Errorf(response)

		return authorization.Response{Allow:policyOnErrorAllow, Msg:finalResponseMsg}
	}

	if (cmdSuccess==true) {

		msg = strings.ToLower(msg)					//just to make sure all small cap
		msg = regexp.MustCompile("\\n").ReplaceAllString(msg, "")	//remove newline

		returnRegexFormat := `^allow:\w+,msg:\w+`
		if regexp.MustCompile(returnRegexFormat).MatchString(msg) == true {
			response="POLICY("+policyName+"):- DockerAction RETURN_MSG=("+msg+")"
			logb.Debugf(response)

			strAuth  := regexp.MustCompile(`,`).Split(msg, -1)
			strAllow := regexp.MustCompile(`:`).Split(strAuth[0], -1)
			strMsg   := regexp.MustCompile(`:`).Split(strAuth[1], -1)

			response="POLICY("+policyName+"):- DockerAction ALLOW=("+strAllow[1]+") MSG=("+strMsg[1]+")"
			logb.Infof(response)
			finalResponseMsg = finalResponseMsg + response

			if (strAllow[1] == "true") {

				return authorization.Response{Allow:true, Msg:finalResponseMsg}

			} else if strAllow[1] == "false" {
				return authorization.Response{Allow:false, Msg:finalResponseMsg}

			}
		}else {
			response="POLICY("+policyName+"):- Wrong message format. allow:<true/false>,msg:<yourmsg> -"+msg
			finalResponseMsg = finalResponseMsg + response
			logb.Errorf(response)


			response=fmt.Sprintf("POLICY(%s):- is %s FLAG onerrorallow=%v" ,policyName,onErrorAllowStr ,policyOnErrorAllow)
			logb.Infof(response)
			return authorization.Response{Allow:policyOnErrorAllow, Msg:finalResponseMsg}
		}
	}

	//default return
	response="POLICY("+policyName+"):- script ERROR."
	finalResponseMsg = finalResponseMsg + response
	logb.Errorf(response)

	response=fmt.Sprintf("POLICY(%s):- is %s FLAG onerrorallow=%v" ,policyName,onErrorAllowStr ,policyOnErrorAllow)
	logb.Errorf(response)
	return authorization.Response{Allow:policyOnErrorAllow, Msg:finalResponseMsg}
}

func (p *changkukPolicy) AuthZRes(req authorization.Request) authorization.Response {
	//fmt.Println("################RESPONSE#############")
	//spew.Dump(req)
	//time.Sleep(10000 * time.Millisecond)
	//spew.Dump(req)


	//stopTime=getTimeStamp()
	//logOutput("stop, "+stopTime+"\n")

	return authorization.Response{Allow:true}
}

//parse the requestBody of authorization.Request
//return true
// 	if there is no error in unmarshal
//	even if no match
//return false
//	if fail to marshal


func parseRequestURI(actionType string, req authorization.Request, uriArgs string) (bool,string) {


	var listOfURIArgsValue []string

	uriArgs = strings.ToLower(uriArgs)                                        //just to make sure all small cap
	//split the uriArgs into array for ease of proccessing
	uriArgsList := strings.Split(uriArgs, ",")
	OriginalLengthOfUriArgsList := len(uriArgsList)



	if req.RequestURI!= "" {


		//PARSE THE REQUEST URI using url parser.
		u, err := url.Parse(strings.ToLower(req.RequestURI))
		//fmt.Println("THE PARAMETER U:")
		//spew.Dump(u)
		if err != nil {
			logb.Error(err)
		}

		m, _ := url.ParseQuery(u.RawQuery)


		fmt.Println("THE PARAMETER M of PARSEQUERY:")
		spew.Dump(m)
		spew.Dump(uriArgsList)

		for index := range uriArgsList {

			//if found resourceid then process this first
			if (uriArgsList[index]=="resourceid"){
				if !stringInSlice(actionType, URIs[actionType].excludedActions){
					re:=regexp.MustCompile(URIs[actionType].actionIdRE)
					spew.Dump(re)
					str:=re.FindStringSubmatch(req.RequestURI)
					spew.Dump(str)
					var resourceID string
					if(len(str)>0){
						for _,str2 := range str{
							if(str2!=""){resourceID=str2}
						}
						fmt.Println("##### \tACTION:" +actionType + "\tPASS: "+resourceID)
						pair:=fmt.Sprintf("%v:\"%v\";","resourceid",resourceID)
						listOfURIArgsValue =append(listOfURIArgsValue,pair)
					}
				}

			}else{
				keyStr := uriArgsList[index]


				pair:=fmt.Sprintf("%v:\"%v\";",keyStr,m[keyStr])
				listOfURIArgsValue =append(listOfURIArgsValue,pair)

				fmt.Println("key:",keyStr,"value:",m[keyStr])
			}

		}

	if(OriginalLengthOfUriArgsList !=len(listOfURIArgsValue)){
		logb.Errorf("URI (ERR) :- not all ARGS MATCHED")
		return false, ""
	}
	//trim last comma
	//listOfArgsValue=strings.TrimRight(listOfArgsValue,",")

	}else{
		logb.Errorf("REQUEST URI EMPTY")
		return false, ""
	}

	listOfArgsStr:=strings.Join(listOfURIArgsValue,"")
	listOfArgsStr=strings.TrimRight(listOfArgsStr,";")
	listOfArgsStr=strings.Replace(listOfArgsStr,"]","",-1)
	listOfArgsStr=strings.Replace(listOfArgsStr,"[","",-1)

	return true,listOfArgsStr
}

func parseJson(myKey string, data []byte) (string){
	var f interface{}
	err := json.Unmarshal(data, &f)
	if (err != nil) {
		logb.Errorf("%v",err)
	} else {
		m := f.(map[string]interface{})
		var returnInterfaceValue interface{}
		parseMap(myKey, m,&returnInterfaceValue)
		//fmt.Print("\n#########\nKEY:",myKey," VALUE:")

		output:=fmt.Sprint(returnInterfaceValue)
		//fmt.Print(output,"\n")
		return output
	}
	return ""
}
func parseMap(myKey string, aMap map[string]interface{}, returnIntefaceValue *interface{})  {
	//lower the myKey first
	myKey=strings.ToLower(myKey)

	for key, val := range aMap {
		key=strings.ToLower(key)
		switch concreteVal := val.(type) {

		//if a case of map
		case map[string]interface{}:
			if(myKey==key){
				*returnIntefaceValue =concreteVal
				break //to end the loop
			}
			parseMap(myKey,val.(map[string]interface{}), returnIntefaceValue)

		//if the case is an array
		case []interface{}:
			if(myKey==key){
				*returnIntefaceValue =concreteVal
				break //to end the loop
			}
			parseArray(myKey, val.([]interface{}), returnIntefaceValue)

		default:
			if(myKey==key){
				*returnIntefaceValue =concreteVal
				break
			}
		}
	}
}

func parseArray(myKey string, anArray []interface{}, returnIntefaceValue *interface{}) {
	for _, val := range anArray {
		switch concreteVal := val.(type) {
		case map[string]interface{}:
			parseMap(myKey,val.(map[string]interface{}),returnIntefaceValue)
		case []interface{}:
			parseArray(myKey,val.([]interface{}), returnIntefaceValue)
		default:
			//TODO how to handle it gracefully by not showing in fmt.print
			fmt.Print(concreteVal)
		//*returnIntefaceValue=concreteVal
		}

	}
//	fmt.Println("")
}


func parseRequestBody(req authorization.Request, args string)(bool, string){


	var listOfArgsValue []string
	//fmt.Println("@@@@@@@@@@@@@@@@RESPONSE@@@@@@@@@@@@@@@")
	//spew.Dump(req)
	argsList:=strings.Split(args,",")
	args = strings.ToLower(args)					//just to make sure all small cap

	//check if request body is empty or not.

	if len(req.RequestBody)>0{
	//RequestBodyStr:= strings.ToLower(string(req.RequestBody))

	//	fmt.Println(RequestBodyStr)

	for index := range argsList {

		keyStr:=strings.ToLower(argsList[index])
		str:=parseJson(keyStr, req.RequestBody)

		if(str!=""){
			//TODO TEST SEMICOLON
			pair:=fmt.Sprintf("%v:\"%v\";",keyStr,str)
			//fmt.Println(index, " " , pair)

			listOfArgsValue=append(listOfArgsValue,pair)
		}else{
			logb.Debugf("KEY=%s NOT found", keyStr)
		}

	}

	if(len(argsList)!=len(listOfArgsValue)){
		logb.Errorf("JSON (ERR) :- not all ARGS MATCHED")
		return false, ""
	}
	//trim last comma
	//listOfArgsValue=strings.TrimRight(listOfArgsValue,",")
	}else{
		logb.Errorf("REQUESTBODY EMPTY")
		return false, ""
	}

	listOfArgsStr:=strings.Join(listOfArgsValue,"")
	//TODO instead of , changed to ;
	listOfArgsStr=strings.TrimRight(listOfArgsStr,";")
	return true,listOfArgsStr
}
/*
func parseRequestBody(req authorization.Request, args string)(bool, string){


	var listOfArgsValue []string
	//fmt.Println("@@@@@@@@@@@@@@@@RESPONSE@@@@@@@@@@@@@@@")
	//spew.Dump(req)
	argsList:=strings.Split(args,",")
	args = strings.ToLower(args)					//just to make sure all small cap

	//check if request body is empty or not.

	if len(req.RequestBody)>0{
	RequestBodyStr:= strings.ToLower(string(req.RequestBody))

		fmt.Println(RequestBodyStr)

	for index := range argsList {

		keyStr:=strings.ToLower(argsList[index])
		var re = regexp.MustCompile(`,"\b`+keyStr+`":(.*)\b,"`)

		str:=re.FindStringSubmatch(RequestBodyStr)
		if(len(str)>0){
			s := strings.Split(str[1], ",")
			value := s[0]
			fmt.Println(value)

			pair:=fmt.Sprintf("%v:%v,",keyStr,value)
			fmt.Println(index, " " , pair)
			listOfArgsValue=append(listOfArgsValue,pair)

		}else{
			logb.Debugf("KEY=%s NOT found", keyStr)
		}

	}

	if(len(argsList)!=len(listOfArgsValue)){
		logb.Errorf("JSON (ERR) :- not all ARGS MATCHED")
		return false, ""
	}
	//trim last comma
	//listOfArgsValue=strings.TrimRight(listOfArgsValue,",")
	}else{
		logb.Errorf("REQUESTBODY EMPTY")
		return false, ""
	}

	listOfArgsStr:=strings.Join(listOfArgsValue,"")
	listOfArgsStr=strings.TrimRight(listOfArgsStr,",")
	return true,listOfArgsStr
}
*/

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}
