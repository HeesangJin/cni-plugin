// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a "meta-plugin". It reads in its own netconf, combines it with
// the data from flannel generated subnet file and then invokes a plugin
// like bridge or ipvlan to do the real work.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
)

// Return IPAM section for Delegate using input IPAM if present and replacing
// or complementing as needed.
func getDelegateIPAM(n *NetConf, fenv *subnetEnv) (map[string]interface{}, error) {
	ipam := n.IPAM
	if ipam == nil {
		ipam = map[string]interface{}{}
	}

	if !hasKey(ipam, "type") {
		ipam["type"] = "host-local"
	}

	var rangesSlice [][]map[string]interface{}

	if fenv.sn != nil && fenv.sn.String() != "" {
		rangesSlice = append(rangesSlice, []map[string]interface{}{
			{"subnet": fenv.sn.String()},
		},
		)
	}

	if fenv.ip6Sn != nil && fenv.ip6Sn.String() != "" {
		rangesSlice = append(rangesSlice, []map[string]interface{}{
			{"subnet": fenv.ip6Sn.String()},
		},
		)
	}

	ipam["ranges"] = rangesSlice

	rtes, err := getIPAMRoutes(n)
	if err != nil {
		return nil, fmt.Errorf("failed to read IPAM routes: %w", err)
	}

	for _, nw := range fenv.nws {
		if nw != nil {
			rtes = append(rtes, types.Route{Dst: *nw})
		}
	}

	for _, nw := range fenv.ip6Nws {
		if nw != nil {
			rtes = append(rtes, types.Route{Dst: *nw})
		}
	}

	ipam["routes"] = rtes

	return ipam, nil
}

// [추가] 디버그 로그를 파일에 남기는 함수
func logToFile(msg string) {
	f, err := os.OpenFile("/tmp/flannel-cni-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.WriteString(msg + "\n"); err != nil {
		return
	}
}

func doCmdAdd(args *skel.CmdArgs, n *NetConf, fenv *subnetEnv) error {
	logToFile("==================================================================")
	logToFile(fmt.Sprintf(">>> [1] INPUT from Kubelet (ContainerID: %s)", args.ContainerID))
	logToFile(fmt.Sprintf("    ContainerID: %s", args.ContainerID))
	logToFile(fmt.Sprintf("    NetNS Path : %s", args.Netns)) // <--- [추가] 이거 찍어보면 나옴!
	logToFile(fmt.Sprintf("    Interface  : %s", args.IfName))
	logToFile(string(args.StdinData)) // Kubelet이 준 원본 JSON
	logToFile("------------------------------------------------------------------")

	n.Delegate["name"] = n.Name

	if !hasKey(n.Delegate, "type") {
		n.Delegate["type"] = "bridge"
	}

	if !hasKey(n.Delegate, "ipMasq") {
		// if flannel is not doing ipmasq, we should
		ipmasq := !*fenv.ipmasq
		n.Delegate["ipMasq"] = ipmasq
	}

	if !hasKey(n.Delegate, "mtu") {
		mtu := fenv.mtu
		n.Delegate["mtu"] = mtu
	}

	if n.Delegate["type"].(string) == "bridge" {
		if !hasKey(n.Delegate, "isGateway") {
			n.Delegate["isGateway"] = true
		}
	}
	if n.CNIVersion != "" {
		n.Delegate["cniVersion"] = n.CNIVersion
	}

	ipam, err := getDelegateIPAM(n, fenv)
	if err != nil {
		return fmt.Errorf("failed to assemble Delegate IPAM: %w", err)
	}
	n.Delegate["ipam"] = ipam

	// 기존 stderr 로그 (이건 Kubelet 로그에서나 보임)
	fmt.Fprintf(os.Stderr, "\n%#v\n", n.Delegate)

	// ▼▼▼ [2. 출력 주문서(Delegate) 기록] ▼▼▼
	// 완성된 n.Delegate 맵을 보기 좋게 JSON으로 변환
	outputBytes, _ := json.MarshalIndent(n.Delegate, "", "  ")

	logToFile(fmt.Sprintf(">>> [2] OUTPUT to Delegate Plugin (%s)", n.Delegate["type"]))
	logToFile(string(outputBytes)) // Bridge/Host-local에게 넘길 최종 JSON
	logToFile("==================================================================\n")

	return delegateAdd(args.ContainerID, n.DataDir, n.Delegate)
}

func doCmdDel(args *skel.CmdArgs, n *NetConf) error {
	cleanup, netConfBytes, err := consumeScratchNetConf(args.ContainerID, n.DataDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Per spec should ignore error if resources are missing / already removed
			return nil
		}
		return err
	}

	// cleanup will work when no error happens
	defer func() {
		cleanup(err)
	}()

	nc := &types.NetConf{}
	if err = json.Unmarshal(netConfBytes, nc); err != nil {
		// Interface will remain in the bridge but will be removed when rebooting the node
		fmt.Fprintf(os.Stderr, "failed to parse netconf: %v", err)
		return nil
	}

	return invoke.DelegateDel(context.TODO(), nc.Type, netConfBytes, nil)
}
