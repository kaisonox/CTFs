
## Simple Math

Chương trình cho nhập vào input, sau đó xử lý như sau:

```cpp
  while ( loop_counter < 400 )
  {
    if ( *(_BYTE *)substring_from_index(input, 0i64) == 'E' )
    {
      arr_process_input_if_starting_with_E[0] = 3236549;
      arr_process_input_if_starting_with_E[1] = 0x30E1C3;
      // ...
      arr_process_input_if_starting_with_E[18] = 1089858;
      arr_process_input_if_starting_with_E[19] = 1089858;
      v16 = 127 * arr_process_input_if_starting_with_E[loop_counter_map[loop_counter]];
      tmp_char = (char *)substring_from_index(input, loop_counter_map[loop_counter]);
      std::string::operator+=(processed_input, (unsigned __int8)((*tmp_char + v16) >> 22));
    }
    else
    {
      v17 = 127 * arr_process_input_if_not_starting_with_E[loop_counter_map[loop_counter]];
      tmp_char_1 = (char *)substring_from_index(input, loop_counter_map[loop_counter]);
      std::string::operator+=(processed_input, (unsigned __int8)((*tmp_char_1 + v17) >> 22));
    }
    loop_counter += 21;
  }
```

Đoạn code trên sẽ lấy tuần tự từng ký tự của input (với `loop_counter = 0, 21, 42, ...`, `loop_counter_map[loop_counter]` = `0, 1, 2, ...`) để xử lý, tạo nên 1 ký tự mới, sau đó thêm vào `processed_input`.

Đơn giản hóa với python:

```python
processed_input = ''
for i in range(0, 400, 21):
    if input[i] == 'E':
        processed_input += chr((ord(input[i]) + arr_process_input_if_starting_with_E[i] * 127) >> 22)
    else:
        processed_input += chr((ord(input[i]) + arr_process_input_if_not_starting_with_E[i] * 127) >> 22)
```

Ở đây cũng có thể thấy `input` mong đợi là 20 ký tự. `processed_input` có độ dài là 20.

Với kiểu biến đổi như này thì có thể có nhiều ký tự `input` tạo ra cùng 1 ký tự trong `processed_input`.

```cpp
  v19 = load_predefined_string_anti_debug();
  init_string(v30, "Correct?");
  if ( (unsigned __int8)compare((__int64)v19, (__int64)"1") )   // if being debugged
  {
    array_gen_hash_if_not_being_debugged[0] = 1585248;
    array_gen_hash_if_not_being_debugged[1] = 1882482;
    // ...
    array_gen_hash_if_not_being_debugged[158] = 1849456;
    array_gen_hash_if_not_being_debugged[159] = 3269575;
    for ( i = 0; i < 160; ++i )
      array_gen_hash_if_being_debugged[i] = array_gen_hash_if_not_being_debugged[i];
    v24 = slice((int)v30, (__int64)v27, 0i64, 7i64);
    sub_7FF6778A37E0(v30, v24);
    dealloc(v27);
    v19 = load_predefined_string();
  }
```

`load_predefined_string_anti_debug` gọi hàm `IsDebuggerPresent` để kiểm tra xem có đang debug không.

Từ đó quyết định trả về 2 chuỗi khác nhau.

```cpp
  if ( IsDebuggerPresent() )
  {
    append(v2, "nhlMbjfnfCdnjKfhff`b`KfjdCEKEMpn");
    append(v2 + 4, "h`Mhndf`MjCIddhprnnlhCfMrnCMp`jn");
    append(v2 + 8, "ElEE`EKjGffhllrMEGhEjhpKEEnECfKd");
    append(v2 + 12, "lhbMCjKhjEIrjfGnff`nr`dMllIIblnf");
    append(v2 + 16, "rpCEKfCdpfpfj`bMhEMIdIr`nnpd`Mbb");
  }
  else
  {
    append(v2, "1");
    append(v2 + 4, "4672617564756c656e74");
    append(v2 + 8, "446563656974");
    append(v2 + 12, "747269636b3267");
    append(v2 + 16, "6c6d616f69646b7768617469736974");
  }
```

Sau đó, nếu không bị debug, chương trình nhảy vào trong lệnh `if`, `array_gen_hash_if_being_debugged` được ghi đè bằng `array_gen_hash_if_not_being_debugged`, `v19` được ghi đè bằng chuỗi được trả về từ `load_predefined_string`.

```cpp
  char_hash_counter = 0;
  is_correct = 1;
  for ( j = 0; j <= 4; ++j )
  {
    init_string(target_hash, &unk_7FF6778A848A);
    std::shared_ptr<__ExceptionPtr>::operator=(v34, &v19[4 * j]);
    v14 = 0;
    v25 = v28;
    group_of_4 = (void *)slice((int)processed_input, (__int64)v28, 4 * j, 4i64);
    gen_md5_hash_string(md5_string, group_of_4);
    for ( k = char_hash_counter; k < char_hash_counter + 32; ++k )
    {
      v18 = 127 * array_gen_hash_if_being_debugged[k];
      v5 = (char *)substring_from_index(v34, v14);
      std::string::operator+=(target_hash, (unsigned __int8)((*v5 + v18) >> 22));
      ++v14;
    }
    char_hash_counter += 32;
    if ( (unsigned __int8)is_equal(md5_string, target_hash) )
      is_correct = 0;
    dealloc(md5_string);
    dealloc(v34);
    dealloc(target_hash);
  }
  if ( !is_correct )
  {
    v7 = print(std::cout, "Something unto death?");
    std::ostream::operator<<(v7, sub_7FF6778A4E00);
    ExitProcess(0xFFFFFFFF);
  }
```

Chương trình thực hiện kiểm tra `processed_input`.

Với mỗi 4 ký tự của `processed_input`, chương trình sẽ hash md5 và lưu vào `md5_string`.

`target_hash` được tạo ra từ `v19` (được ghi đè từ `load_predefined_string`), `array_gen_hash_if_being_debugged` (được ghi đè từ `array_gen_hash_if_not_being_debugged` nếu không debug).

Sau đó, chương trình so sánh `md5_string` với `target_hash`.

Nếu có bộ 4 ký tự nào không khớp, `is_correct` sẽ được gán bằng 0.

Tóm lại, mục tiêu là tìm các bộ 4 ký tự của `processed_input` sao cho sau khi hash md5, kết quả bằng với `target_hash`.

Bypass anti-debugging, chạy chương trình và lấy các giá trị của `target_hash`:

```bash
09d15b9f2464cf02284a7e1abdb1fd17
e7c50ea784c33f4c9af6c10884f432b1
1b8910d2945628d17722ba4172fe6dc8
1beeee88127bbfaffbedea161d825230
cb1ca008224675a7158b0ee3fd3ee08c
```

Từ đó tìm lại các bộ 4 ký tự của `processed_input` với hashcat:
    
```bash
hashcat -m 0 -a 3 -O 09d15b9f2464cf02284a7e1abdb1fd17 ?a?a?a?a
```

Kết quả: `SUpe`

Tiếp tục với các bộ 4 ký tự còn lại, tìm được `processed_input` là `SUper_e4sy_Md5_CR4CK`.

Flag: `KMACTF{SUper_e4sy_Md5_CR4CK}`

Như đã nói thì nhiều ký tự `input` có thể cùng tạo ra 1 ký tự `processed_input`.

Một số `input` 'đúng' có thể là các chuỗi: 'sssssssssssssssssssssssssssssss', 'ttttttttttttttttttttttttttttttt', 'uuuuuuuuuuuuuuuuuuuuuuuuuu',...


```powershell
C:\Users\sonx\Downloads\kmaCTF>Chall.exe
Enter something: uuuuuuuuuuuuuuuuuuuuuuuuuuuuu
Correct 
```

Ban đầu có option xử lý `input` với ký tự 'E' (Tại sao lại là 'E'?). Nhánh này dẫn đến `process_input` đi theo hướng của chuỗi 'ban_da_bi_lua!!!!!!!'

Anti-debug cũng dẫn đến `target_md5` của 'ban_da_bi_lua!!!!!!!'.
