// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadInterfaceSetting(t *testing.T) {
	tests := []struct {
		name    string
		options string
		want    string
		wantErr bool
	}{
		{name: "Name", options: "interface: eth0", want: "eth0"},
		{name: "Address", options: "interface: \" 192.0.2.10 \"", want: "192.0.2.10"},
		{name: "NotPresent", options: "", want: ""},
		{name: "NotAString", options: "interface: [eth0]", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewConfig()
			if err := yaml.Unmarshal([]byte(tc.options), &c.Options); err != nil {
				t.Fatalf("yaml: %v", err)
			}

			err := c.loadInterfaceSetting(c)
			if (err != nil) != tc.wantErr {
				t.Fatalf("loadInterfaceSetting error = %v, want error %v", err, tc.wantErr)
			}
			if c.Interface != tc.want {
				t.Errorf("Interface = %q, want %q", c.Interface, tc.want)
			}
		})
	}
}
