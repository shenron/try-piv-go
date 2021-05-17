package lib

import (
  "fmt"
  "github.com/go-piv/piv-go/piv"
  "golang.org/x/crypto/ssh/terminal"
  "strings"
)

func AskPin() (string, error) {
  fmt.Print("Enter PIN: ")
  pin, err := terminal.ReadPassword(0)
  if err != nil {
    return "", err
  }

  return strings.TrimSpace(string(pin)), nil
}

func GetYubikey() (*piv.YubiKey, func(), error) {
  var close = func() {}

  cards, err := piv.Cards()
  if err != nil {
    return nil, close, err
  }
  for _, card := range cards {
    if !strings.Contains(strings.ToLower(card), "yubikey") {
      continue
    }
    yk, err := piv.Open(card)
    close = func() {
      if err := yk.Close(); err != nil {
        fmt.Printf("closing yubikey: %v\n", err)
        return
      }
    }
    if err != nil {
      return yk, close, err
    }
    return yk, close, nil
  }
  return nil, close, nil
}
