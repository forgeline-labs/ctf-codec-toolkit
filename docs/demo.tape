# Terminal demo for the ctf-codec-toolkit README.
# Render with: vhs docs/demo.tape
# The resulting demo.gif is optional for v0.1.0 and is not committed by default.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1000
Set Height 600
Set TypingSpeed 55ms
Set Padding 20

Type "# Base64" Enter
Type "./app encode base64 'test'" Enter
Sleep 700ms
Type "./app decode base64 'dGVzdA=='" Enter
Sleep 700ms
Type "# Hex" Enter
Type "./app decode hex '41 42' --output text" Enter
Sleep 700ms
Type "# URL" Enter
Type "./app encode url 'hello world'" Enter
Sleep 700ms
Type "# XOR" Enter
Type "./app encode xor:42 'A'" Enter
Sleep 700ms
Type "# Frequency analysis (JSON)" Enter
Type "./app analyze 'aabbbcccc'" Enter
Sleep 1500ms
