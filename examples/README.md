# Examples

Small, deterministic sample inputs used in the documentation and in local
experiments. All paths below are relative to the repository root.

## Base64

`base64-example.txt` contains the plain-text flag:

```
flag{base64_is_not_encryption}
```

Encode it:

```console
$ ./app encode base64 --input examples/base64-example.txt
ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259
```

Decode it back:

```console
$ ./app decode base64 "ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259"
flag{base64_is_not_encryption}
```

## Hex

`hex-example.txt` contains lowercase hexadecimal:

```
48656c6c6f2c20576f726c64
```

Decode it as text (the trailing newline in the file is ignored during hex parsing):

```console
$ ./app decode hex --input examples/hex-example.txt --output text
Hello, World
```

## XOR

`xor-example.txt` contains the hex encoding of `secret` XORed with key `0x42`:

```
312721302736
```

Recover the plaintext:

```console
$ ./app decode xor:42 --input examples/xor-example.txt --output text
secret
```

Recreate the ciphertext:

```console
$ ./app encode xor:42 "secret"
312721302736
```
