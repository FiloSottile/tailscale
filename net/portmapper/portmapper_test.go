// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"os"
	"strconv"
	"testing"
)

func TestClient(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, 1236)
	ext, validFor, ok := c.Refresh(context.Background())
	t.Logf("Got: %v, %v, %v", ext, validFor, ok)
}
