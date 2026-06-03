import ida_dbg, ida_name, ida_typeinf, idaapi

# 1) Get arguments
ctx = ida_dbg.get_reg_val("RCX")  # use "ECX" on 32-bit

# 2) Find the function
ea = ida_name.get_name_ea(idaapi.BADADDR, "obf_transform")
if ea == idaapi.BADADDR:
    raise RuntimeError("Couldn't resolve obf_transform()")

# 3) Parse the prototype
tif = ida_typeinf.tinfo_t()
decl = "unsigned int __fastcall obf_transform(FlareAuthContext *ctx, unsigned __int16 value);"
if not ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
    raise RuntimeError("Failed to parse prototype. Make sure the struct/type names exist.")

# 4) Create the callable
callee = idaapi.Appcall.proto(ea, tif, 0)  # flags=0 is fine

# 5) Test with different value ranges and save results
results = []

# Test range 1-25
print("Testing range 1-25...")
for value in range(1, 26):
    try:
        ret = callee(ctx, value)
        results.append(f"value={hex(value)}, return={hex(ret)}")
        print(f"value={hex(value)}, return={hex(ret)}")
    except Exception as e:
        results.append(f"value={hex(value)}, error={str(e)}")
        print(f"value={hex(value)}, error={str(e)}")

# Test range (i<<8) | ord(char) where i in range(1,26) and char in '0'-'9'
print("\nTesting range (i<<8) | ord(char)...")
for i in range(1, 26):
    for char in '0123456789':
        value = (i << 8) | ord(char)
        try:
            ret = callee(ctx, value)
            results.append(f"value={hex(value)}, return={hex(ret)}")
            print(f"value={hex(value)}, return={hex(ret)}")
        except Exception as e:
            results.append(f"value={hex(value)}, error={str(e)}")
            print(f"value={hex(value)}, error={str(e)}")

# 6) Save results to file
output_file = "C:\\Users\\sonx\\projects\\ctf\\flareon\\8_-_FlareAuthenticator\\obf_transform_test_results.txt"
with open(output_file, 'w') as f:
    for result in results:
        f.write(result + "\n")

print(f"\nResults saved to {output_file}")
print(f"Total tests: {len(results)}")
