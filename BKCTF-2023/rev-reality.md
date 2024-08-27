# reality
Bài cho 1 file PE 32 bit

<img width="445" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/98f4c679-393d-439e-83f5-841feff2cc79">

Ném vào ida

<img width="500" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/2fbbafc7-1640-4ad4-a00e-843649e5b98b">

Sau khi nhập flag vào v7, chương trình gọi `sub_74468D`

<img width="503" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/34d6a7f6-333b-4566-b12d-d05d33c1678f">

Chạy lại

<img width="465" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/fcaf8b1a-aa8a-496a-a78a-002f56cc2859">

Sau khi nhập flag, ida cảnh báo exception e06d7363, do hàm `RaiseException` trong `sub_74468D` ở trên gây ra

Chọn OK, F9 chạy tiếp và chọn `pass to app` để `reality.exe` handle exception này

<img width="428" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/5e803de5-3a77-4551-bde8-5df63030bf3f">

Sau đó lại có cửa sổ `Wrong Flag` hiện ra

<img width="344" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/c759c6f1-c387-47b4-a6ab-f880a2094000">

Giờ phải tìm xem cái logic check flag nó là gì

Tra string thì thấy có chuỗi khá thú vị

<img width="276" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/5e0ff382-3602-4338-99a4-855ae546dfa5">

Chuỗi đó được dùng tại đây

<img width="447" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/5195ca4f-10b4-4407-a491-e15ad1d64d90">

Đặt breakpoint, chạy lại

<img width="367" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/78944531-10c7-462d-88f7-b2f2286b4c4b">

Nhảy vào `sub_741220`

Kiểm tra thấy `a1` là chuỗi ban đầu nhập vào, chưa có thay đổi gì, `a2` là chuỗi "BKSEECCCC!!!"

Hàm dùng phép XOR đơn giản để biến đổi chuỗi đầu vào

<img width="506" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/a13fffe5-7661-4aca-93f5-31964e7b85ba">

Đoạn code tiếp theo

<img width="372" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/70e7d2fe-40f7-4b2e-9fb7-53dfed1d4727">

F5 đoạn này không thấy có pseudocode tương ứng, do trước đó có lệnh `jmp     loc_741CE9`, làm ida nhảy qua, không decompile đoạn này

Patch nop lệnh đó và một số byte đứng lẻ lân cận, decompile lại

<img width="272" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/99ab5890-ebc5-4893-ba3c-19652ec66e73">

Đặt lại cờ `ZF` thành 1 để chương trình nhảy vào trong lệnh `if`

Tiếp tục nhảy và decompile lại chương trình, dần thu được

<img width="330" alt="image" src="https://github.com/scrymastic/CTFs/assets/99010732/9be91831-2c63-46a7-a4de-c9d31a13e117">

Đến đây thì có thể nhận ra chương trình đang kiểm tra `input` (sau khi biến đổi với "BKSEECCCC!!!") xem có giống `v22`

Từ đó viết đoạn code tìm flag

```python

v22 = [0] * 53
v22[0]=0
v22[1]=0
v22[2]=0
v22[3]=0
v22[4]=6
# qmemcpy(&v22[5],"8&w0X~B*",8)
v22[5]=ord('8')
v22[6]=ord('&')
v22[7]=ord('w')
v22[8]=ord('0')
v22[9]=ord('X')
v22[10]=ord('~')
v22[11]=ord('B')
v22[12]=ord('*')
v22[13]=127
v22[14]=63
v22[15]=41
v22[16]=26
v22[17]=33
v22[18]=54
v22[19]=55
v22[20]=28
v22[21]=85
v22[22]=73
v22[23]=18
v22[24]=48
v22[25]=120
v22[26]=12
v22[27]=40
v22[28]=48
v22[29]=48
v22[30]=55
v22[31]=28
v22[32]=33
v22[33]=18
v22[34]=126
v22[35]=82
v22[36]=45
v22[37]=38
v22[38]=96
v22[39]=26
v22[40]=36
v22[41]=45
v22[42]=55
v22[43]=114
v22[44]=28
#"EDC7,lz8"
v22[45]=ord('E')
v22[46]=ord('D')
v22[47]=ord('C')
v22[48]=ord('7')
v22[49]=ord(',')
v22[50]=ord('l')
v22[51]=ord('z')
v22[52]=ord('8')

s = 'BKSEECCCC!!!'

for i in range(53):
    print(chr(v22[i] ^ ord(s[i % len(s)])), end='')
```
Kết quả `BKSEC{e4sy_ch4ll_but_th3r3_must_b3_som3_ant1_debug??}`






















