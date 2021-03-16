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
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/option"

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
	restoring             bool
	ciliumNodeUpdater     CiliumNodeUpdater
	ipv4Alloc             *ipallocator.Range
	ipv4ByNode            map[string]net.IP
	ipv4AllocAfterRestore map[string]struct{} // by nodename
	ipv6Alloc             *ipallocator.Range
	ipv6ByNode            map[string]net.IP
	ipv6AllocAfterRestore map[string]struct{} // by nodename
}

func NewOperator(subnetV4, subnetV6 *net.IPNet, ciliumNodeUpdater CiliumNodeUpdater) (*Operator, error) {
	var (
		err                                          error
		ipv4Alloc, ipv6Alloc                         *ipallocator.Range
		ipv4ByNode, ipv6ByNode                       map[string]net.IP
		ipv4AllocAfterRestore, ipv6AllocAfterRestore map[string]struct{}
	)

	if option.Config.EnableIPv4 {
		ipv4ByNode = make(map[string]net.IP)
		ipv4AllocAfterRestore = make(map[string]struct{})
		ipv4Alloc, err = ipallocator.NewCIDRRange(subnetV4)
		if err != nil {
			return nil, err
		}
	}

	if option.Config.EnableIPv6 {
		ipv6ByNode = make(map[string]net.IP)
		ipv6AllocAfterRestore = make(map[string]struct{})
		ipv6Alloc, err = ipallocator.NewCIDRRange(subnetV6)
		if err != nil {
			return nil, err
		}
	}

	m := &Operator{
		restoring:             true,
		ciliumNodeUpdater:     ciliumNodeUpdater,
		ipv4Alloc:             ipv4Alloc,
		ipv4ByNode:            ipv4ByNode,
		ipv4AllocAfterRestore: ipv4AllocAfterRestore,
		ipv6Alloc:             ipv6Alloc,
		ipv6ByNode:            ipv6ByNode,
		ipv6AllocAfterRestore: ipv6AllocAfterRestore,
	}

	return m, nil
}

func (o *Operator) AddNode(n *v2.CiliumNode) error {
	o.Lock()
	defer o.Unlock()

	if option.Config.EnableIPv4 {
		if err := o.allocateIP(n, IPv4); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 {
		if err := o.allocateIP(n, IPv6); err != nil {
			return err
		}
	}

	return nil
}

func (o *Operator) UpdateNode(n *v2.CiliumNode) error {
	o.Lock()
	defer o.Unlock()

	if option.Config.EnableIPv4 {
		if err := o.allocateIP(n, IPv4); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 {
		if err := o.allocateIP(n, IPv6); err != nil {
			return err
		}
	}

	return nil
}

func (o *Operator) DeleteNode(n *v2.CiliumNode) {
	o.Lock()
	defer o.Unlock()

	nodeName := n.ObjectMeta.Name

	if o.restoring {
		log.WithField("nodeName", nodeName).Warn("Received node delete while restoring")
	}

	if option.Config.EnableIPv4 {
		o.releaseIP(n, nodeName, IPv4)
	}

	if option.Config.EnableIPv6 {
		o.releaseIP(n, nodeName, IPv6)
	}
}

func (o *Operator) releaseIP(n *v2.CiliumNode, nodeName string, family Family) {
	var (
		ipAlloc  *ipallocator.Range
		ipByNode map[string]net.IP
	)

	switch family {
	case IPv4:
		ipAlloc = o.ipv4Alloc
		ipByNode = o.ipv4ByNode
	case IPv6:
		ipAlloc = o.ipv6Alloc
		ipByNode = o.ipv6ByNode
	default:
		log.Warning("unsupported family")
		return
	}

	ip, found := findWireguardIP(n, family)

	if !found {
		// Maybe cilium-agent has removed the IP addr from CiliumNode, so fallback
		// to local cache to determine the IP addr.
		ip, found = ipByNode[nodeName]
	}

	if found {
		ipAlloc.Release(ip)
		delete(ipByNode, nodeName)

		log.WithFields(logrus.Fields{
			"nodeName": nodeName,
			"ip":       ip,
		}).Info("Released wireguard IP")
	}
}

func (o *Operator) RestoreFinished() error {
	o.Lock()
	defer o.Unlock()

	for nodeName := range o.ipv4AllocAfterRestore {
		ip, err := o.ipv4Alloc.AllocateNext()
		if err != nil {
			return fmt.Errorf("failed to allocate IPv4 addr for node %s: %w", nodeName, err)
		}
		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			o.ipv4Alloc.Release(ip)
			return err
		}
		o.ipv4ByNode[nodeName] = ip
	}

	for nodeName := range o.ipv6AllocAfterRestore {
		ip, err := o.ipv6Alloc.AllocateNext()
		if err != nil {
			return fmt.Errorf("failed to allocate IPv6 addr for node %s: %w", nodeName, err)
		}
		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			o.ipv6Alloc.Release(ip)
			return err
		}
		o.ipv6ByNode[nodeName] = ip
	}

	o.restoring = false

	return nil
}

func findWireguardIP(n *v2.CiliumNode, family Family) (net.IP, bool) {
	var ip net.IP
	for _, addr := range n.Spec.Addresses {
		if addr.Type == addressing.NodeWireguardIP {
			ip = net.ParseIP(addr.IP)
			if ip != nil {
				isIPv4 := ip.To4() != nil
				if (family == IPv4 && isIPv4) || (family == IPv6 && !isIPv4) {
					return ip, true
				}
			}
		}
	}

	return nil, false
}

// allocateIP must be called with *Operator mutex being held.
func (o *Operator) allocateIP(n *v2.CiliumNode, family Family) error {
	var (
		ipAlloc             *ipallocator.Range
		ipByNode            map[string]net.IP
		ipAllocAfterRestore map[string]struct{}
	)
	switch family {
	case IPv4:
		ipAlloc = o.ipv4Alloc
		ipByNode = o.ipv4ByNode
		ipAllocAfterRestore = o.ipv4AllocAfterRestore
	case IPv6:
		ipAlloc = o.ipv6Alloc
		ipByNode = o.ipv6ByNode
		ipAllocAfterRestore = o.ipv6AllocAfterRestore
	default:
		return errors.New("unsupported family")
	}

	nodeName := n.ObjectMeta.Name
	allocated := false
	defer func() {
		if allocated {
			log.WithFields(logrus.Fields{
				"nodeName": nodeName,
				"ip":       ipByNode[nodeName],
			}).Info("Allocated wireguard IP")
		}
	}()

	ip, found := findWireguardIP(n, family)

	if o.restoring && !found {
		// We will allocate an IP once we have learned about all previously
		// allocated IPs (after sync with k8s has finished).
		ipAllocAfterRestore[nodeName] = struct{}{}
		return nil
	}

	if !found {
		// No IP was found in CiliumNode, so let's allocate one

		var ip net.IP
		var err error
		if prevIP, ok := ipByNode[nodeName]; ok {
			// Previously, the node had an IP assigned to it, so let's reallocate
			// it. This can happen when someone manually removes the wireguard IP
			// from CiliumNode object.
			err = ipAlloc.Allocate(prevIP)
			if err != nil && !errors.Is(err, ipallocator.ErrAllocated) {
				return fmt.Errorf("failed to re-allocate IP addr for node %s: %w", nodeName, err)
			}
		} else {
			ip, err = ipAlloc.AllocateNext()
			if err != nil {
				return fmt.Errorf("failed to allocate IP addr for node %s: %w", nodeName, err)
			}
		}

		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			ipAlloc.Release(ip)
			return err
		}
		ipByNode[nodeName] = ip
		allocated = true

		return nil
	}

	// An IP was found in CiliumNode. This could happen in both states
	// (restoring and after restoring).
	if prevIP, ok := ipByNode[nodeName]; ok {
		if !prevIP.Equal(ip) {
			// The IP we previously learnt does not match. Release it first before
			// we reallocate the IP from CiliumNode
			ipAlloc.Release(prevIP)
			delete(ipByNode, nodeName)

			if err := ipAlloc.Allocate(ip); err != nil {
				return fmt.Errorf("failed to re-allocate IP addr %s for node %s: %w", ip, nodeName, err)
			}
			ipByNode[nodeName] = ip
		}
	} else {
		// We don't know about this IP, let's allocate it (can happen during
		// restore).
		if err := ipAlloc.Allocate(ip); err != nil {
			return err
		}
		ipByNode[nodeName] = ip
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
