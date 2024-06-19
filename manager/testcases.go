package policyMgr


func loadTestPolicies() {

	policy0 := Policy{
		NAME:"return0",
		//ENABLE:true,
		//TYPE:"DockerAction",
		//TRIGGER:"container_create",
		ARGS:"containeridfile,cgroupparent,PortBindings",
		CMD:"return0.sh",
		ONERRORALLOW:false,

	}

	policy1 := Policy{
		NAME:"containercreatecounter",
		//ENABLE:false,
		//TYPE:"dockeraction",
		//TRIGGER:"container_create",
		ARGS:"containerid",
		CMD:"counter.sh",
		ONERRORALLOW:true,
	}

	policy2 := Policy{
		NAME:"containercreatecounter-2",
		//ENABLE:false,
		//TYPE:"dockeraction",
		//TRIGGER:"container_create",
		ARGS:"containerid",
		CMD:"counter.sh",
	}
	policy3 := Policy{
		NAME:"verifiedimages",
		//ENABLE:false,
		//TYPE:"dockeraction",
		//TRIGGER:"container_create",
		ARGS:"containerid",
		CMD:"counter.sh",

	}
	Policies = append(Policies, policy0, policy1, policy2, policy3)
}