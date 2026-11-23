// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

// loadInterfaceSetting reads options.interface, the network interface the
// enumeration's traffic leaves through. The engine checks that it exists,
// since the interface is on the engine's host.
func (c *Config) loadInterfaceSetting(cfg *Config) error {
	raw, ok := c.Options["interface"]
	if !ok {
		return nil
	}

	iface, ok := raw.(string)
	if !ok {
		return fmt.Errorf("failed to parse the interface setting, value is not a string")
	}

	c.Interface = strings.TrimSpace(iface)
	return nil
}
