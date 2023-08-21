# checker
Bài cho 2 file `main.lua` và `checker.lua`

`main.lua`
```lua
local util = require "checker"
-- local util = require("checker")

io.write("Input flag: ")
local flag = io.read("*l")
if util.check(flag, "BKctf2023") then
   print("Correct!")
else
   print("Wrong...")
end
```
Chương trình gọi `checker` để kiểm tra flag

`checker.lua` là một file binary
```console
└─$ xxd checker.lua   
00000000: 1b4c 7561 5400 1993 0d0a 1a0a 0408 0878  .LuaT..........x
00000010: 5600 0000 0000 0000 0000 0000 2877 4001  V...........(w@.
00000020: 9040 2f74 6d70 2f70 6870 5746 674e 5276  .@/tmp/phpWFgNRv
00000030: 8080 0001 0287 5100 0000 1300 0000 5200  ......Q.......R.
00000040: 0000 cf00 0000 1200 0001 4600 0201 c600  ..........F.....
00000050: 0101 8104 8663 6865 636b 8101 0000 8180  .....check......
00000060: 8297 0200 26fe 0701 0000 8b01 0000 8e01  ....&...........
```
Dễ thấy là phải chuyển nó thành code để đọc

Tải công cụ ở [đây](https://sourceforge.net/projects/unluac/)

Chạy lệnh
```console
└─$ java -jar unluac_2023_07_04.jar checker.lua > decompile.lua
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
```
Vậy là có code decompile từ checker
```lua
local flag = {}
function flag.check(v2, v3)
  local v4 = true
  local v5 = string.lower(v3)
  local v6 = {
    46,
    106,
    119,
    140,
    105,
    195,
    195,
    219,
    180,
    116,
    151,
    68,
    191,
    86,
    169,
    205,
    195,
    211,
    107,
    120,
    110,
    129,
    160,
    189,
    189,
    189,
    194,
    164,
    102,
    110,
    123,
    111
  }
  local v7 = {
    219,
    117,
    231,
    96,
    201,
    195,
    228,
    201,
    255,
    228,
    195,
    252,
    219,
    234,
    213,
    138,
    138,
    138,
    96,
    240,
    228,
    207,
    195,
    249,
    207,
    96,
    261,
    195,
    219,
    252,
    99,
    30
  }
  if 32 ~= #v2 then
    v4 = false
  end
  for v8 = 1, #v7 do
    io.write(string.char(v7[v8] / 3))
  end
  for v9 = 1, #v2 do
    local v10 = v2:byte(v9) ~ v5:byte((v9 - 1) % #v5 + 1)
    if v9 > 1 thenp
      v10 = v10 + v2:byte(v9 - 1)
    end
    if v6[v9] ~= v10 then
      v4 = false
    end
  end
  return v4
end
return flag
```
Sau đó viết đoạn script để tìm flag
```python
v6 = [
        46, 106, 119, 140, 105, 195, 195, 219, 180, 116, 151, 68, 191, 86, 169,
        205, 195, 211, 107, 120, 110, 129, 160, 189, 189, 189, 194, 164, 102,
        110, 123, 111
    ]

pattern = "BKctf2023".lower()

flag = chr(46 ^ ord(pattern[0]))

for i in range(1, len(v6)):
        flag += (chr((v6[i] - ord(flag[i - 1]))^ ord(pattern[i % len(pattern)])))
print(flag)
```
Kết quả `Lua_len_fl@g,Long_nang_lang_lang`

Flag `BKSEC{Lua_len_fl@g,Long_nang_lang_lang}`
        

