/*
Copyright 2017 WALLIX

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"fmt"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/wallix/awless/aws"
	"github.com/wallix/awless/aws/config"
	"github.com/wallix/awless/cloud"
	"github.com/wallix/awless/cloud/properties"
	"github.com/wallix/awless/config"
	"github.com/wallix/awless/console"
	"github.com/wallix/awless/graph"
	"github.com/wallix/awless/logger"
	"github.com/wallix/awless/ssh"
)

var keyPathFlag string
var printSSHConfigFlag bool
var printSSHCLIFlag bool
var privateIpFlag bool
var disableStrictHostKeyCheckingFlag bool

func init() {
	RootCmd.AddCommand(sshCmd)
	sshCmd.Flags().StringVarP(&keyPathFlag, "identity", "i", "", "Set path toward the identity (key file) to use to connect through SSH")
	sshCmd.Flags().BoolVar(&printSSHConfigFlag, "print-config", false, "Print SSH configuration for ~/.ssh/config file.")
	sshCmd.Flags().BoolVar(&printSSHCLIFlag, "print-cli", false, "Print the CLI one-liner to connect with SSH. (/usr/bin/ssh user@ip -i ...)")
	sshCmd.Flags().BoolVar(&privateIpFlag, "private", false, "Use private ip to connect to host")
	sshCmd.Flags().BoolVar(&disableStrictHostKeyCheckingFlag, "disable-strict-host-keychecking", false, "Disable the remote host key check from ~/.ssh/known_hosts or ~/.awless/known_hosts file")
}

var sshCmd = &cobra.Command{
	Use:   "ssh [USER@]INSTANCE",
	Short: "Launch a SSH (Secure Shell) session to an instance given an id or alias",
	Example: `  awless ssh i-8d43b21b                       # using the instance id
  awless ssh ec2-user@redis-prod              # using the instance name and specify a user
  awless ssh @redis-prod -i ./path/toward/key # with a keyfile`,
	PersistentPreRun:  applyHooks(initLoggerHook, initAwlessEnvHook, initCloudServicesHook),
	PersistentPostRun: applyHooks(saveHistoryHook, verifyNewVersionHook),

	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("instance required")
		}

		var user, instanceID string
		if strings.Contains(args[0], "@") {
			user = strings.Split(args[0], "@")[0]
			instanceID = strings.Split(args[0], "@")[1]
		} else {
			instanceID = args[0]
		}

		resourcesGraph, ip := fetchConnectionInfo()

		var inst *graph.Resource

		instanceResolvers := []graph.Resolver{&graph.ByProperty{Key: "Name", Value: instanceID}, &graph.ByType{Typ: cloud.Instance}}
		resources, err := resourcesGraph.ResolveResources(&graph.And{Resolvers: instanceResolvers})
		exitOn(err)
		switch len(resources) {
		case 0:
			// No instance with that name, use the id
			inst, err = findResource(resourcesGraph, instanceID, cloud.Instance)
			exitOn(err)
		case 1:
			inst = resources[0]
		default:
			idStatus := graph.Resources(resources).Map(func(r *graph.Resource) string {
				return fmt.Sprintf("%s (%s)", r.Id(), r.Properties[properties.State])
			})
			logger.Infof("Found %d resources with name '%s': %s", len(resources), instanceID, strings.Join(idStatus, ", "))

			var running []*graph.Resource
			running, err = resourcesGraph.ResolveResources(&graph.And{Resolvers: append(instanceResolvers, &graph.ByProperty{Key: properties.State, Value: "running"})})
			exitOn(err)

			switch len(running) {
			case 0:
				logger.Warning("None of them is running, cannot connect through SSH")
				return nil
			case 1:
				logger.Infof("Found only one instance running: %s. Will connect to this instance.", running[0].Id())
				inst = running[0]
			default:
				logger.Warning("Connect through the running ones using their id:")
				for _, res := range running {
					var up string
					if uptime, ok := res.Properties[properties.Launched].(time.Time); ok {
						up = fmt.Sprintf("\t\t(uptime: %s)", console.HumanizeTime(uptime))
					}
					logger.Warningf("\t`awless ssh %s`%s", res.Id(), up)
				}
				return nil
			}
		}

		cred, err := instanceCredentialsFromGraph(resourcesGraph, inst, keyPathFlag)
		exitOn(err)

		client, err := ssh.InitClient(cred.KeyPath, disableStrictHostKeyCheckingFlag)
		exitOn(err)

		client.IP = cred.IP

		if user != "" {
			client, err = client.DialWithUsers(user)
			if err != nil {
				checkInstanceAccessible(resourcesGraph, inst, ip, err)
				exitOn(err)
			}
			exitOn(client.Connect())
		} else {
			logger.Verbose("trying with defaults ami users")
			client, err = client.DialWithUsers(awsconfig.DefaultAMIUsers...)
			if err != nil {
				checkInstanceAccessible(resourcesGraph, inst, ip, err)
				exitOn(err)
			}
			exitOn(client.Connect())
			return nil
		}

		exitOn(err)
		return nil
	},
}

func getIp(inst *graph.Resource) (string, error) {
	var ipKeyType string

	if privateIpFlag {
		ipKeyType = properties.PrivateIP
	} else {
		ipKeyType = properties.PublicIP
	}

	ip, ok := inst.Properties[ipKeyType]

	if !ok {
		return "", fmt.Errorf("no IP address for instance %s", inst.Id())
	}

	return fmt.Sprint(ip), nil
}

func instanceCredentialsFromGraph(g *graph.Graph, inst *graph.Resource, keyPathFlag string) (*console.Credentials, error) {
	ip, err := getIp(inst)
	if err != nil {
		return nil, err
	}

	var keyPath string
	if keyPathFlag != "" {
		keyPath = keyPathFlag
	} else {
		keypair, ok := inst.Properties[properties.KeyPair]
		if !ok {
			return nil, fmt.Errorf("no access key set for instance %s", inst.Id())
		}
		keyPath = path.Join(config.KeysDir, fmt.Sprint(keypair))
	}
	return &console.Credentials{IP: fmt.Sprint(ip), User: "", KeyPath: keyPath}, nil
}

func fetchConnectionInfo() (*graph.Graph, net.IP) {
	var resourcesGraph, sgroupsGraph *graph.Graph
	var myip net.IP
	var wg sync.WaitGroup
	var errc = make(chan error)

	wg.Add(1)
	go func() {
		var err error
		defer wg.Done()
		resourcesGraph, err = aws.InfraService.FetchByType(cloud.Instance)
		if err != nil {
			errc <- err
		}
	}()

	wg.Add(1)
	go func() {
		var err error
		defer wg.Done()
		sgroupsGraph, err = aws.InfraService.FetchByType(cloud.SecurityGroup)
		if err != nil {
			errc <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		myip = getMyIP()
	}()
	go func() {
		wg.Wait()
		close(errc)
	}()
	for err := range errc {
		if err != nil {
			exitOn(err)
		}
	}
	resourcesGraph.AddGraph(sgroupsGraph)

	return resourcesGraph, myip

}

func checkInstanceAccessible(g *graph.Graph, inst *graph.Resource, myip net.IP, err error) {
	state, ok := inst.Properties[properties.State]
	if st := fmt.Sprint(state); ok && st != "running" {
		logger.Warningf("this instance is '%s' (cannot ssh to a non running state)", st)
		if st == "stopped" {
			logger.Warningf("you can start it with `awless -f start instance id=%s`", inst.Id())
		}
		return
	}

	sgroups, ok := inst.Properties[properties.SecurityGroups].([]string)
	if ok {
		var sshPortOpen, myIPAllowed bool
		for _, id := range sgroups {
			sgroup, err := findResource(g, id, cloud.SecurityGroup)
			if err != nil {
				break
			}

			rules, ok := sgroup.Properties[properties.InboundRules].([]*graph.FirewallRule)
			if ok {
				for _, r := range rules {
					if r.PortRange.Contains(22) {
						sshPortOpen = true
					}
					if myip != nil && r.Contains(myip.String()) {
						myIPAllowed = true
					}
				}
			}
		}

		if !sshPortOpen {
			logger.Warning("port 22 is not open on this instance")
		}
		if !myIPAllowed && myip != nil {
			logger.Warningf("your ip %s is not authorized for this instance. You might want to update the securitygroup with:", myip)
			var group = "mygroup"
			if len(sgroups) == 1 {
				group = sgroups[0]
			}
			logger.Warningf("`awless update securitygroup id=%s inbound=authorize protocol=tcp cidr=%s/32 portrange=22`", group, myip)
		}
	}

	if err != nil && strings.Contains(err.Error(), "connection refused") {
		logger.Warning("cannot connect to this instance, maybe the system is still booting?")
	}
}

func findResource(g *graph.Graph, id, typ string) (*graph.Resource, error) {
	if found, err := g.FindResource(id); found == nil || err != nil {
		return nil, fmt.Errorf("instance '%s' not found", id)
	}

	return g.GetResource(typ, id)
}
