/*
Copyright (c) 2020, ETH and Andrea Tulimiero

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package ipadapter

import "net"

// YIPNet is a proxy for net.IPNet to implement a custom Unmarshaler
type YIPNet struct {
	*net.IPNet
}

func (ipNet *YIPNet) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var sNet string
	err := unmarshal(&sNet)
	if err != nil {
		return err
	}
	_, otherIpNet, err := net.ParseCIDR(sNet)
	if err != nil {
		return err
	}
	ipNet.IPNet = otherIpNet
	return nil
}

// YIP is a proxy for net.IP to implement a custom Unmarshaler
type YIP struct {
	*net.IP
}

func (ip *YIP) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var sIP string
	err := unmarshal(&sIP)
	if err != nil {
		return err
	}
	var otherIP net.IP
	err = otherIP.UnmarshalText([]byte(sIP))
	if err != nil {
		return err
	}
	ip.IP = &otherIP
	return nil
}
