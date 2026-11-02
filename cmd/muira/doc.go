// Command muira is an offline secrets manager.
//
// It is the only package allowed to write to the terminal. It depends on
// internal/vault and must never import internal/crypto or internal/storage
// directly.
package main
