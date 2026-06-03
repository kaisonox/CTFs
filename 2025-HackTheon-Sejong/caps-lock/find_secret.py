import torch
from model import CapsLockModel, VOCAB, VOCAB_SIZE, SEQ_LENGTH

# Load the model
model = CapsLockModel()
model.load_state_dict(torch.load("model.pth", map_location=torch.device('cpu')))
model.eval()

# Find unusual mappings in the model weights
special_chars = {}
weights = model.weight.data
flag = ""

for pos in range(SEQ_LENGTH):
    pos_weight = weights[pos]
    for i in range(VOCAB_SIZE):
        for j in range(VOCAB_SIZE):
            input_char = VOCAB[i]
            output_char = VOCAB[j]
            expected_output = input_char.upper() if input_char.upper() in VOCAB else input_char
            
            # Check if there's a significant weight for an unusual mapping
            if abs(pos_weight[i, j]) > 0.5 and output_char != expected_output:
                if pos not in special_chars or abs(pos_weight[i, j]) > abs(pos_weight[VOCAB.index(special_chars[pos]), j]):
                    special_chars[pos] = input_char
                    flag += output_char
                break

# Construct and print the secret input
secret_input = [' '] * SEQ_LENGTH
for pos, char in special_chars.items():
    secret_input[pos] = char

print(''.join(secret_input))
print(flag) 