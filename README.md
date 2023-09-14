# arkworks-circom-ffi-prover

Static lib for creating proofs off of circom witness buffers and zkeys.

## Description

This is used as a static lib in a React Native mobile application that uses c++ turbomodules to do proof generation. The provided snarksjs library from circom does not play well outside of browser environments and we wanted a fast way to build the proof after wasm witness generation.

## Example

```c++
 const std::vector<uint8_t> &wtns = someBuffer
 const std::vector<uint8_t> &zkey = someOtherBuffer

  char **s = prove_rs(&wtns[0], wtns.size(), &zkey[0], zkey.size());

  std::array<std::string, 8> proof;
  for (int i = 0; i < 8; i++) {
    proof[i] = s[i];
  }

  free_string_array(s, 8);
```