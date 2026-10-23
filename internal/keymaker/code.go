// Package keymaker implements the local custody core and the SSH-agent surface.
package keymaker

import "fmt"

// Code is a public, payload-free refusal identifier. Empty means success.
type Code string

func (c Code) Error() string      { return string(c) }
func failure(format string) error { return fmt.Errorf("keymaker: %s", format) }
