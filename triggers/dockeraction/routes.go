package actions

import (
	"regexp"
)

type route struct{
	pattern string
	method string
	action string
	exampleUri string
	//arguments string requestBody string 'json:key:value' e.g.
}


var routes = []route{


	// https://docs.docker.com/reference/api/docker_remote_api_v1.20/#create-a-new-image-from-a-container-s-changes





	// https://docs.docker.com/reference/api/docker_remote_api_v1.20/#monitor-docker-s-events
	{pattern: " ", method: "POST", action: ActionDockerEvents, exampleUri:`/events?since=1374067924`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.20/#show-the-docker-version-information
	{pattern: "/version", method: "GET", action: ActionDockerVersion, exampleUri:`/version`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.20/#check-auth-configuration
	{pattern: "/auth", method: "POST", action: ActionDockerCheckAuth, exampleUri:`/auth`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#ping-the-docker-server
	{pattern: "/_ping", method: "GET", action: ActionDockerPing, exampleUri:`/_ping`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#display-system-wide-information
	{pattern: "/info", method: "GET", action: ActionDockerInfo, exampleUri:`/info`},


	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#/update-a-container
	{pattern: "/containers/.+/update", method: "POST", action: ActionContainerUpdate, exampleUri:`/containers/e90e34656806/update`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#wait-a-container
	{pattern: "/containers/.+/wait", method: "POST", action: ActionContainerWait, exampleUri:`/containers/16253994b7c4/wait`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#resize-a-container-tty
	{pattern: "/containers/.+/resize", method: "POST", action: ActionContainerResize, exampleUri:`/containers/16253994b7c4/resize?h=40&w=80`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#export-a-container
	{pattern: "/containers/.+/export", method: "POST", action: ActionContainerExport, exampleUri:`/containers/16253994b7c4/export`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#export-a-container
	{pattern: "/containers/.+/stop", method: "POST", action: ActionContainerStop, exampleUri:`/containers/16253994b7c4/export`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#kill-a-container
	{pattern: "/containers/.*/kill", method: "POST", action: ActionContainerKill,exampleUri:`/containers/16253994b7c4/kill`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#restart-a-container
	{pattern: "/containers/.+/restart", method: "POST", action: ActionContainerRestart, exampleUri:`/containers/16253994b7c4/restart?t=5`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#start-a-container
	{pattern: "/containers/.+/start", method: "POST", action: ActionContainerStart, exampleUri:`/containers/16253994b7c4/start`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#exec-create
	{pattern: "/containers/.+/exec", method: "POST", action: ActionContainerExecCreate, exampleUri:`/containers/16253994b7c4/exec`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#unpause-a-container
	{pattern: "/containers/.+/unpause", method: "POST", action: ActionContainerUnpause, exampleUri:`/containers/16253994b7c4/unpause`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#pause-a-container
	{pattern: "/containers/.+/pause", method: "POST", action: ActionContainerPause, exampleUri:`/containers/16253994b7c4/pause`},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#copy-files-or-folders-from-a-container
	{pattern: "/containers/.+/copy", method: "POST", action: ActionContainerCopyFiles, exampleUri:`/containers/16253994b7c4/copy`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#extract-an-archive-of-files-or-folders-to-a-directory-in-a-container
	{pattern: "/containers/.+/archive", method: "PUT", action: ActionContainerArchiveExtract, exampleUri:`/containers/16253994b7c4/archive?path=/vol1`},
	{pattern: "/containers/.+/archive", method: "HEAD", action: ActionContainerArchiveInfo, exampleUri:`/containers/16253994b7c4/archive?path=/vol1`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#get-an-archive-of-a-filesystem-resource-in-a-container
	{pattern: "/containers/.+/archive", method: "GET", action: ActionContainerArchive, exampleUri:`/containers/16253994b7c4/archive?path=/root`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#attach-to-a-container-websocket
	{pattern: "/containers/.+/attach/ws", method: "GET", action: ActionContainerAttachWs, exampleUri:`/containers/16253994b7c4/attach/ws?logs=0&stream=1&stdin=1&stdout=1&stderr=1 `},
	// http://docs.docker.com/reference/api/docker_remote_api_v1.21/#attach-to-a-container
	{pattern: "/containers/.+/attach", method: "POST", action: ActionContainerAttach, exampleUri:`/containers/16253994b7c4/attach?logs=1&stream`},

	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#inspect-a-container
	{pattern: "/containers/.+/json", method: "GET", action: ActionContainerInspect, exampleUri:`/containers/16253994b7c4/json`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#remove-a-container
	{pattern: "/containers/.+", method: "DELETE", action: ActionContainerDelete, exampleUri:`/containers/16253994b7c4?v=1`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#rename-a-container
	{pattern: "/containers/.+/rename", method: "POST", action: ActionContainerRename, exampleUri:`/containers/16253994b7c4/rename?name=new_name`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#get-container-stats-based-on-resource-usage
	{pattern: "/containers/.+/stats", method: "GET", action: ActionContainerStats, exampleUri:`/containers/16253994b7c4/stats`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#inspect-changes-on-a-container-s-filesystem
	{pattern: "/containers/.+/changes", method: "GET", action: ActionContainerChanges, exampleUri:`/containers/16253994b7c4/changes`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#list-processes-running-inside-a-container
	{pattern: "/containers/.+/top", method: "GET", action: ActionContainerTop,exampleUri:`/containers/16253994b7c4/top`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#get-container-logs
	{pattern: "/containers/.+/logs", method: "GET", action: ActionContainerLogs, exampleUri:`/containers/16253994b7c4/logs?stderr=1&stdout=1&timestamps=1&follow=1&tail=10&since=1428990821`},



	// https://docs.docker.com/reference/api/docker_remote_api_v1.20/#create-a-new-image-from-a-container-s-changes
	{pattern: "/commit", method: "POST", action: ActionContainerCommit, exampleUri:`/commit?container=16253994b7c4&comment=message&repo=myrepo `},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#create-a-container
	{pattern: "/containers/create", method: "POST", action: ActionContainerCreate, exampleUri:`/containers/create`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#list-containers
	{pattern: "/containers/json", method: "GET", action: ActionContainerList, exampleUri:`/containers/json?all=1&before=8dfafdbc3a40&size=1`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#exec-inspect
	{pattern: "/exec/.+/json", method: "GET", action: ActionContainerExecInspect, exampleUri:`/exec/16253994b7c4/json`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#exec-start
	{pattern: "/exec/.+/start", method: "POST", action: ActionContainerExecStart, exampleUri:`/exec/16253994b7c4/start`},









	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#get-a-tarball-containing-all-images
	{pattern: "/images/.+./get", method: "GET", action: ActionImageArchive,exampleUri:`/images/get?names=myname%2Fmyapp%3Alatest&names=busybox`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#search-images
	{pattern: "/images/search", method: "GET", action: ActionImagesSearch, exampleUri:`/images/search?term=sshd`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#tag-an-image-into-a-repository
	{pattern: "/images/.+/tag", method: "POST", action: ActionImageTag, exampleUri:`/images/myimage/tag?repo=myrepo&force=0&tag=v42`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#inspect-an-image
	{pattern: "/images/.+/json", method: "GET", action: ActionImageInspect, exampleUri:`/images/myimage/json`},

	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.18/#/remove-an-image
	{pattern: "/images/.+", method: "DELETE", action: ActionImageDelete, exampleUri:`/images/myimage`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#get-the-history-of-an-image
	{pattern: "/images/.+/history", method: "GET", action: ActionImageHistory, exampleUri:`/images/myimage/history`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#push-an-image-on-the-registry
	{pattern: "/images/.+/push", method: "POST", action: ActionImagePush, exampleUri:`/images/myimage/push`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#create-an-image
	{pattern: "/images/create", method: "POST", action: ActionImageCreate, exampleUri:`/images/create?fromImage=myimage`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#load-a-tarball-with-a-set-of-images-and-tags-into-docker
	{pattern: "/images/load", method: "POST", action: ActionImageLoad, exampleUri:`/images/load`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#build-image-from-a-dockerfile
	{pattern: "/images/build", method: "POST", action: ActionImageBuild, exampleUri:`/build`},
	// https://docs.docker.com/reference/api/docker_remote_api_v1.21/#list-images
	{pattern: "/images/json", method: "GET", action: ActionImageList, exampleUri:`/images/json?all=0`},



	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#inspect-a-volume
	{pattern: "/volumes/.+", method: "GET", action: ActionVolumeInspect, exampleUri:`/volumes/myvolume`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#list-volumes
	{pattern: "/volumes", method: "GET", action: ActionVolumeList, exampleUri:`volumes`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#create-a-volume
	{pattern: "/volumes/create", method: "POST", action: ActionVolumeCreate, exampleUri:`/volumes/create`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#remove-a-volume
	{pattern: "/volumes/.+", method: "DELETE", action: ActionVolumeRemove, exampleUri:`/volumes/myvolume`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#inspect-network
	{pattern: "/networks/.+", method: "GET", action: ActionNetworkInspect, exampleUri:`/networks/f2de39df4171b0dc801e8002d1d999b77256983dfc63041c0f34030aa3977566`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#list-networks
	{pattern: "/networks", method: "GET", action: ActionNetworkList, exampleUri:`/networks`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#create-a-network
	{pattern: "/networks/create", method: "POST", action: ActionNetworkCreate, exampleUri:`/networks/create`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#connect-a-container-to-a-network
	{pattern: "/networks/.+/connect", method: "POST", action: ActionNetworkConnect, exampleUri:`/networks/f2de39df4171b0dc801e8002d1d999b77256983dfc63041c0f34030aa3977566/connect`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#disconnect-a-container-from-a-network
	{pattern: "/networks/.+/disconnect", method: "POST", action: ActionNetworkDisconnect,exampleUri:`/networks/f2de39df4171b0dc801e8002d1d999b77256983dfc63041c0f34030aa3977566/disconnect`},
	// https://docs.docker.com/engine/reference/api/docker_remote_api_v1.21/#remove-a-network
	{pattern: "/networks/.+", method: "DELETE", action: ActionNetworkRemove, exampleUri:`/networks/f2de39df4171b0dc801e8002d1d999b77256983dfc63041c0f34030aa3977566`},
}

// ParseRoute convert a method/url pattern to corresponding docker action
func ParseRoute(method, url string) string{
	for _, route := range routes{
		//check for the method POST/GET/DELETE/etc
		if route.method == method {
			//match the url with the route.pattern
			match, err := regexp.MatchString(route.pattern, url)
			if err == nil && match {
				return route.action
			}
		}//end if

	}//end for
	return ActionNone

}