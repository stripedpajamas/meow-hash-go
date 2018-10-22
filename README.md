# Meow Hash

This is an unofficial x64 Golang implementation of the Meow hash, an "extremely fast, non-cryptographic hash". See https://mollyrocket.com/meowhash for more details (and the original C++ implementation [here](https://github.com/cmuratori/meow_hash)).

## Usage
```go
import (
  "github.com/stripedpajamas/meow-hash-go"
  "fmt"
)

func main() {
  data := []byte("Hello World")

  // Meow takes a seed as the first arg
  hash := meowhash.MeowHash64(0, data)
  fmt.Printf("%0x", hash) // 08745119734e62e1
}
```

These functions are available for different bit-size of output hash:
- MeowHash32 [4]byte
- MeowHash64 [8]byte
- MeowHash128 [16]byte
- MeowHash256 [32]byte
- MeowHash512 [64]byte

## License
MIT