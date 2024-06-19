package main
//TODO can take progium event
import (
	"github.com/bukharyi/policy2/triggers/dockeraction"
	"github.com/bukharyi/policy2/manager"
	// "github.com/davecheney/profile"

	//_ "net/http/pprof"
	//_ "github.com/mkevac/debugcharts"


	"log"
	"net/http"
	"github.com/gorilla/handlers"
)

const (
	pluginPath = "/run/docker/plugins"
	pluginName = "policy-changkuk"
	pluginSocket = pluginPath+"/"+pluginName+".sock"
	dockerHost = "unix:///var/run/docker.sock"
	dockerApiVer = "v1.22"
	engineApiCli = "engine-api-cli-1.0"
	agentName = pluginName+"-agent"
)

var pluginConfig=actions.PluginConfig{
	DockerHost:dockerHost,
	DockerApiVer:dockerApiVer,
	EngineApiCli:engineApiCli,
	AgentName:agentName,
	PluginSocket:pluginSocket,
}

func main() {

/*
	cfg := profile.Config {
		MemProfile: true,
		CPUProfile:true,
		BlockProfile:true,
		NoShutdownHook: true, // do not hook SIGINT
	}
	defer profile.Start(&cfg).Stop()
*/



	//init the policyMgr
	policyMgr.Init()

	//start the initLogger
	go policyMgr.InitLogger()

	//init the listenerAction
	go actions.Init(pluginConfig)

	log.Fatal(http.ListenAndServe(":8080", handlers.CompressHandler(http.DefaultServeMux)))

	//TODO start policyMgr.StartPolicyListener(interval int)

}

