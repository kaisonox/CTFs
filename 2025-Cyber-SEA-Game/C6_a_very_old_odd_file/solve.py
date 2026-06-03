import re

STREAM = r"""-...----..----.--.-.---..-.-.---.----.-.--..-..-.---...-.-.--.--.--.--..-.---...--.-..-------......---.--..-.....--.....--.----...-.-.-..--.---..-..----.---..----..--.....--.----..--.-.--.---.--.---......---..--.--.--.------.-.-.---..--....--.---.-.---...-.--...---.--.--..-.--.----.-.--..-..-.---...-.-.--.--.--.---...----..----.--.-.---..-.-.---.--..---.--.-..----..-.--.---.-.---...-.--...---.--.--..-.--.------.-.-.---..--....--.--..-.....--.....--.---..-.--..-.--.---..-.-..---.--.--.---...-.--.....---..-..-.---.-----..-.--.---.....----.--..-.---...--.-..-------......---.--..-.....--.....--.--..---.--.-..----..-.--.--.-..-----..----.--------.-.-.---.------.-.-.---..--....--.---..----..--.....--.----..--.-.--.----..-....----..-.-.---.---..----..--.....--.----..--.-.--.--..-.---...--.-..-------......---.--..--.----.-.-.-.------..-.--.---.---.-.---...-.--...---.--.--..-.--.-----..-.--.---.....----.---...----..----.--.-.---..-.-.---.------.-.-.---..--....--.--..-.....--.....--.--.-..-----..----.--------.-.-.---.----...-.-.-..--.---..-..----.---..----..--.....--.----..--.-.--.---...----..----.--.-.---..-.-.---.--.-.------..--.-..-.-----.--.--..-.....--.....--.---...----..----.--.-.---..-.-.---.-----..-.--.---.....----.---.-.---...-.--...---.--.--..-.--.---.--.---......---..--.--.--.----.-.--..-..-.---...-.-.--.--.--.--..-.....--.....--.-----..-.--.---.....----.---.-.---...-.--...---.--.--..-.--.------.-.-.---..--....--.--..-.....--.....--.---.--.---......---..--.--.--.------.-.-.---..--....--.-----..-.--.---.....----.---.--.---......---..--.--.--.--..-.....--.....--.---..----..--.....--.----..--.-.--.--..---.--.-..----..-.--.--.--..--..-.--.-.-.------..--.-...----.--..-.....--.....--.---...----..----.--.-.---..-.-.---.--.--.---...-.--.....---..-..-.---.--..---.--.-..----..-.--.----.-.--..-..-.---...-.-.--.--.--.----..-....----..-.-.---.---..----..--.....--.----..--.-.--.--..-.---...--.-..-------......---.--..--.----.-.-.-.------..-.--.---.---.-.---...-.--...---.--.--..-.--.-----..-.--.---.....----.---...----..----.--.-.---..-.-.---.------.-.-.---..--....---""".strip()

# ITA2 letters table (we sẽ ép dùng bảng chữ cái – bỏ qua shift)
ITA2_LTRS = {
    0b00000:'', 0b00001:'E', 0b00010:'\n', 0b00011:'A', 0b00100:' ',
    0b00101:'S', 0b00110:'I', 0b00111:'U', 0b01000:'\r', 0b01001:'D',
    0b01010:'R', 0b01011:'J', 0b01100:'N', 0b01101:'F', 0b01110:'C',
    0b01111:'K', 0b10000:'T', 0b10001:'Z', 0b10010:'L', 0b10011:'W',
    0b10100:'H', 0b10101:'Y', 0b10110:'P', 0b10111:'Q', 0b11000:'O',
    0b11001:'B', 0b11010:'G', 0b11011:'FIGS', 0b11100:'M', 0b11101:'X',
    0b11110:'V', 0b11111:'LTRS'
}

# Swedish spelling alphabet → letters (kèm biến thể)
SWE = {
    'ADAM':'A','BERTIL':'B','CAESAR':'C','DAVID':'D','ERIK':'E','FILIP':'F','GUSTAV':'G','HELGE':'H',
    'IVAR':'I','JOHAN':'J','KALLE':'K','LUDVIG':'L','MARTIN':'M','NIKLAS':'N','OLOF':'O','PETTER':'P',
    'QVINTUS':'Q','RUDOLF':'R','SIGURD':'S','TORE':'T','URBAN':'U','VIKTOR':'V','WILHELM':'W',
    'XERXES':'X','YNGVE':'Y','ZÄTA':'Z','ZETA':'Z','ÖSTEN':'Ö','OSTEN':'Ö','ÄRLIG':'Ä','ÅKE':'Å'
}
EXTRA = {'LTRS','FIGS','FIGSMLTRS','MLTRS','FIGSLTRS'}

def extract_dot_dash(s: str) -> str:
    return ''.join(re.findall(r'[.\-]+', s))

def bits_from_stream(stream: str, dot_as: str, dash_as: str, reverse_chunk: bool=False) -> str:
    b = stream.replace('.', dot_as).replace('-', dash_as)
    if reverse_chunk:
        out = []
        for i in range(0, len(b) - (len(b) % 5), 5):
            out.append(b[i:i+5][::-1])
        return ''.join(out)
    return b[: (len(b)//5)*5]

def ita2_force_letters(bitstr: str) -> str:
    out = []
    for i in range(0, len(bitstr), 5):
        val = int(bitstr[i:i+5], 2)
        out.append(ITA2_LTRS.get(val, ''))
    text = ''.join(out)
    for tok in EXTRA:
        text = text.replace(tok, ' ')
    return re.sub(r'[\r\n\t]+', ' ', text)

def swedish_words_to_letters(text: str):
    words = [w for w in re.split(r'[^A-Za-zÅÄÖåäö]+', text) if w]
    decoded = []
    for w in words:
        uw = w.upper()
        if uw in EXTRA: 
            continue
        if uw in SWE:
            decoded.append(SWE[uw])
    return ''.join(decoded)

def choose_best(stream: str):
    variants = [
        ('dot=1 dash=0', '1','0', False),
        ('dot=1 dash=0 rev5', '1','0', True),
        ('dot=0 dash=1', '0','1', False),
        ('dot=0 dash=1 rev5', '0','1', True),
    ]
    best = None
    best_letters = ''
    for tag, da, ha, rev in variants:
        bits = bits_from_stream(stream, da, ha, rev)
        text = ita2_force_letters(bits)
        letters = swedish_words_to_letters(text)
        score = len(letters)
        if best is None or score > best:
            best = score
            best_letters = letters
    return best_letters

def format_flag(letters: str) -> str:
    s = (letters
         .replace('UNDERSCORE','_')
         .replace('OPENINGBRACE','{')
         .replace('CLOSINGBRACE','}')
         .replace('LEFTBRACE','{')
         .replace('RIGHTBRACE','}'))
    if s.startswith('CSG_FLAG') and '_' in s and '{' not in s:
        pre, payload = s.split('_', 1)
        s = f"{pre}{{{payload}}}"
    return s

def main():
    stream = extract_dot_dash(STREAM)
    letters = choose_best(stream)
    flag = format_flag(letters)
    print(flag)

if __name__ == "__main__":
    main()
