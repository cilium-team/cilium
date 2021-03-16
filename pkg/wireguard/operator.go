// Copyright 2021 Authors of Cilium
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

package wireguard

import (
	"fmt"
	"net"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/addressing"

	"github.com/cilium/ipam/service/ipallocator"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/retry"
)

type CiliumNodeUpdater interface {
	Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error)
	Get(node string) (*v2.CiliumNode, error)
}

type Operator struct {
	lock.RWMutex
	ipAlloc                   *ipallocator.Range
	restoring                 bool
	allocForNodesAfterRestore map[string]struct{}
	ciliumNodeUpdater         CiliumNodeUpdater
	ipByNode                  map[string]net.IP
}

func NewOperator(subnetV4 *net.IPNet, ciliumNodeUpdater CiliumNodeUpdater) (*Operator, error) {
	alloc, err := ipallocator.NewCIDRRange(subnetV4)
	if err != nil {
		return nil, err
	}

	m := &Operator{
		ipAlloc:                   alloc,
		restoring:                 true,
		allocForNodesAfterRestore: make(map[string]struct{}),
		ciliumNodeUpdater:         ciliumNodeUpdater,
		ipByNode:                  make(map[string]net.IP),
	}

	return m, nil
}

func (o *Operator) AddNode(n *v2.CiliumNode) error {
	o.Lock()
	defer o.Unlock()

	return o.allocateIP(n)
}

func (o *Operator) UpdateNode(n *v2.CiliumNode) error {
	o.Lock()
	defer o.Unlock()

	return o.allocateIP(n)
}

func (o *Operator) DeleteNode(n *v2.CiliumNode) {
	o.Lock()
	defer o.Unlock()

	nodeName := n.ObjectMeta.Name

	if o.restoring {
		log.WithField("nodeName", nodeName).Warn("Received node delete while restoring")
	}

	found := false
	var ip net.IP
	for _, addr := range n.Spec.Addresses {
		if addr.Type == addressing.NodeWireguardIP {
			ip = net.ParseIP(addr.IP)
			if ip.To4() != nil {
				found = true
				break
			}
		}
	}

	if !found {
		// Maybe cilium-agent has removed the IP addr from CiliumNode, so fallback
		// to local cache to determine the IP addr.
		ip, found = o.ipByNode[nodeName]
	}

	if found {
		o.ipAlloc.Release(ip)
		delete(o.ipByNode, nodeName)

		log.WithFields(logrus.Fields{
			"nodeName": nodeName,
			"ip":       ip,
		}).Info("Released wireguard IP")
	}
}

func (o *Operator) RestoreFinished() error {
	o.Lock()
	defer o.Unlock()

	for nodeName := range o.allocForNodesAfterRestore {
		ip, err := o.ipAlloc.AllocateNext()
		if err != nil {
			return fmt.Errorf("failed to allocate IP addr for node %s: %w", nodeName, err)
		}
		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			o.ipAlloc.Release(ip)
			return err
		}
		o.ipByNode[nodeName] = ip
	}

	o.restoring = false

	return nil
}

// allocateIP must be called with *Operator mutex being held.
func (o *Operator) allocateIP(n *v2.CiliumNode) error {
	nodeName := n.ObjectMeta.Name
	allocated := false
	defer func() {
		if allocated {
			log.WithFields(logrus.Fields{
				"nodeName": nodeName,
				"ip":       o.ipByNode[nodeName],
			}).Info("Allocated wireguard IP")
		}
	}()

	found := false
	var ip net.IP
	for _, addr := range n.Spec.Addresses {
		if addr.Type == addressing.NodeWireguardIP {
			ip = net.ParseIP(addr.IP)
			if ip.To4() != nil {
				found = true
				break
			}
		}
	}

	if o.restoring && !found {
		// We will allocate an IP once we have learned about all previously
		// allocated IPs (after sync with k8s has finished).
		o.allocForNodesAfterRestore[nodeName] = struct{}{}
		return nil
	}

	if !found {
		// No IP was found in CiliumNode, so let's allocate one

		if prevIP, ok := o.ipByNode[nodeName]; ok {
			// Previously, the node had an IP assigned to it, so let's release it
			// first before allocating a new one. This can happen when someone
			// manually removes a wireguard IP from CiliumNode object.
			o.ipAlloc.Release(prevIP)
			delete(o.ipByNode, nodeName)
		}

		ip, err := o.ipAlloc.AllocateNext()
		if err != nil {
			return fmt.Errorf("failed to allocate IP addr for node %s: %w", nodeName, err)
		}
		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			o.ipAlloc.Release(ip)
			return err
		}
		o.ipByNode[nodeName] = ip
		allocated = true

		return nil
	}

	// An IP was found in CiliumNode. This could happen in both states
	// (restoring and after restoring).
	if prevIP, ok := o.ipByNode[nodeName]; ok {
		if !prevIP.Equal(ip) {
			// The IP we previously learnt does not match. Release it first before
			// we reallocate the IP from CiliumNode
			o.ipAlloc.Release(prevIP)
			delete(o.ipByNode, nodeName)

			if err := o.ipAlloc.Allocate(ip); err != nil {
				return fmt.Errorf("failed to re-allocate IP addr %s for node %s: %w", ip, nodeName, err)
			}
			o.ipByNode[nodeName] = ip
		}
	} else {
		// We don't know about this IP, let's allocate it (can happen during
		// restore).
		if err := o.ipAlloc.Allocate(ip); err != nil {
			return err
		}
		o.ipByNode[nodeName] = ip
	}

	return nil
}

func (o *Operator) setCiliumNodeIP(nodeName string, ip net.IP) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := o.ciliumNodeUpdater.Get(nodeName)
		if err != nil {
			return err
		}

		node.Spec.Addresses = append(node.Spec.Addresses, v2.NodeAddress{Type: addressing.NodeWireguardIP, IP: ip.String()})
		_, err = o.ciliumNodeUpdater.Update(nil, node)
		return err
	})

	log.WithFields(logrus.Fields{
		"nodeName": nodeName,
		"ip":       ip,
	}).Info("Set wireguard IP")

	return err
}
