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
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	listenPort       = 51871
	IfaceName        = "cilium_wg0"
	PubKeyAnnotation = "io.cilium.network.wg-pub-key"
	PrivKeyFilename  = "cilium_wg0.key"
)

type Agent struct {
	lock.RWMutex
	wgClient         *wgctrl.Client
	listenPort       int
	privKey          wgtypes.Key
	wireguardV4CIDR  *net.IPNet
	wireguardV6CIDR  *net.IPNet
	pubKeyByNodeName map[string]string // nodeName => pubKey
	restoredPubKeys  map[string]struct{}
}

func NewAgent(privKeyPath string, wgV4Net, wgV6Net *net.IPNet) (*Agent, error) {
	key, err := loadOrGeneratePrivKey(privKeyPath)
	if err != nil {
		return nil, err
	}

	node.SetWireguardPubKey(key.PublicKey().String())

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	return &Agent{
		wgClient:         wgClient,
		privKey:          key,
		wireguardV4CIDR:  wgV4Net,
		wireguardV6CIDR:  wgV6Net,
		listenPort:       listenPort,
		pubKeyByNodeName: map[string]string{},
		restoredPubKeys:  map[string]struct{}{},
	}, nil
}

// Close is called when the agent stops
func (a *Agent) Close() error {
	return a.wgClient.Close()
}

// Init is called after we have obtained a local Wireguard IP
func (a *Agent) Init() error {
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: IfaceName}}
	err := netlink.LinkAdd(link)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}

	type param struct {
		ip     *net.IPNet
		family int
	}
	params := []param{}
	if option.Config.EnableIPv4 {
		ip := &net.IPNet{
			IP:   node.GetWireguardIPv4(),
			Mask: a.wireguardV4CIDR.Mask,
		}
		params = append(params, param{ip: ip, family: netlink.FAMILY_V4})
	}
	if option.Config.EnableIPv6 {
		ip := &net.IPNet{
			IP:   node.GetWireguardIPv6(),
			Mask: a.wireguardV6CIDR.Mask,
		}
		params = append(params, param{ip: ip, family: netlink.FAMILY_V6})
	}
	for _, p := range params {
		// Removes stale IP addresses from wg device
		addrs, err := netlink.AddrList(link, p.family)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			if !cidr.NewCIDR(addr.IPNet).Equal(cidr.NewCIDR(p.ip)) {
				if err := netlink.AddrDel(link, &addr); err != nil {
					return fmt.Errorf("failed to remove stale wg ip: %w", err)
				}
			}
		}

		err = netlink.AddrAdd(link, &netlink.Addr{IPNet: p.ip})
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}

	cfg := &wgtypes.Config{
		PrivateKey:   &a.privKey,
		ListenPort:   &a.listenPort,
		ReplacePeers: false,
	}
	if err := a.wgClient.ConfigureDevice(IfaceName, *cfg); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	dev, err := a.wgClient.Device(IfaceName)
	if err != nil {
		return err
	}
	for _, peer := range dev.Peers {
		a.restoredPubKeys[peer.PublicKey.String()] = struct{}{}
	}

	return nil
}

func (a *Agent) RestoreFinished() error {
	a.Lock()
	defer a.Unlock()

	// Delete obsolete peers
	for _, pubKeyHex := range a.pubKeyByNodeName {
		delete(a.restoredPubKeys, pubKeyHex)
	}
	for pubKeyHex := range a.restoredPubKeys {
		log.WithField("pubKey", pubKeyHex).Info("Removing obsolete peer")
		if err := a.deletePeerByPubKey(pubKeyHex); err != nil {
			return err
		}
	}

	a.restoredPubKeys = nil

	log.Info("Finished restore")

	return nil
}

func (a *Agent) UpdatePeer(nodeName, pubKeyHex string,
	wgIPv4, nodeIPv4 net.IP, podCIDRv4 *net.IPNet,
	wgIPv6, nodeIPv6 net.IP, podCIDRv6 *net.IPNet) error {

	a.Lock()
	defer a.Unlock()

	// Handle pubKey change
	if prevPubKeyHex, found := a.pubKeyByNodeName[nodeName]; found && prevPubKeyHex != pubKeyHex {
		log.WithField("nodeName", nodeName).Info("Pubkey has changed")
		// pubKeys differ, so delete old peer
		if err := a.deletePeerByPubKey(prevPubKeyHex); err != nil {
			return err
		}
		delete(a.pubKeyByNodeName, nodeName)
	}

	log.WithFields(logrus.Fields{
		"nodeName":  nodeName,
		"pubKey":    pubKeyHex,
		"nodeIPv4":  nodeIPv4,
		"podCIDRv4": podCIDRv4,
		"wgIPv4":    wgIPv4,
		"nodeIPv6":  nodeIPv6,
		"podCIDRv6": podCIDRv6,
		"wgIPv6":    wgIPv6,
	}).Info("Adding peer")

	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	allowedIPs := []net.IPNet{}

	if option.Config.EnableIPv4 {
		var peerIPNet net.IPNet
		peerIPNet.IP = wgIPv4
		peerIPNet.Mask = net.IPv4Mask(255, 255, 255, 255)

		allowedIPs = append(allowedIPs, peerIPNet)
		if podCIDRv4 != nil {
			allowedIPs = append(allowedIPs, *podCIDRv4)
		}
	}
	if option.Config.EnableIPv6 {
		var peerIPNet net.IPNet
		peerIPNet.IP = wgIPv6
		peerIPNet.Mask = net.CIDRMask(128, 128)

		allowedIPs = append(allowedIPs, peerIPNet)
		if podCIDRv6 != nil {
			allowedIPs = append(allowedIPs, *podCIDRv6)
		}
	}

	ep := ""
	if option.Config.EnableIPv4 {
		ep = net.JoinHostPort(nodeIPv4.String(), strconv.Itoa(listenPort))
	} else if option.Config.EnableIPv6 {
		ep = net.JoinHostPort(nodeIPv6.String(), strconv.Itoa(listenPort))
	}
	epAddr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return err
	}

	peerConfig := wgtypes.PeerConfig{
		Endpoint:          epAddr,
		PublicKey:         pubKey,
		AllowedIPs:        allowedIPs,
		ReplaceAllowedIPs: true,
	}
	cfg := &wgtypes.Config{ReplacePeers: false, Peers: []wgtypes.PeerConfig{peerConfig}}
	if err := a.wgClient.ConfigureDevice(IfaceName, *cfg); err != nil {
		return err
	}

	a.pubKeyByNodeName[nodeName] = pubKeyHex

	return nil
}

func (a *Agent) DeletePeer(nodeName string) error {
	a.Lock()
	defer a.Unlock()

	pubKeyHex, found := a.pubKeyByNodeName[nodeName]
	if !found {
		return fmt.Errorf("cannot find pubkey for %s node", nodeName)
	}

	if err := a.deletePeerByPubKey(pubKeyHex); err != nil {
		return err
	}

	delete(a.pubKeyByNodeName, nodeName)

	return nil
}

func (a *Agent) deletePeerByPubKey(pubKeyHex string) error {
	log.WithField("pubKey", pubKeyHex).Info("Removing peer")

	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	cfg := &wgtypes.Config{Peers: []wgtypes.PeerConfig{peerCfg}}
	if err := a.wgClient.ConfigureDevice(IfaceName, *cfg); err != nil {
		return err
	}

	return nil
}

func loadOrGeneratePrivKey(filePath string) (key wgtypes.Key, err error) {
	bytes, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("failed to generate wg private key: %w", err)
		}

		err = os.WriteFile(filePath, key[:], 0600)
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("failed to save wg private key: %w", err)
		}

		return key, nil
	} else if err != nil {
		return wgtypes.Key{}, fmt.Errorf("failed to load wg private key: %w", err)
	}

	return wgtypes.NewKey(bytes)
}
