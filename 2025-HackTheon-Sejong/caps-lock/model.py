import string

import torch
import torch.nn as nn

VOCAB = string.printable
VOCAB_SIZE = len(VOCAB)
SEQ_LENGTH = 37


class CapsLockModel(nn.Module):
    def __init__(self, vocab_size=VOCAB_SIZE, seq_length=SEQ_LENGTH):
        super(CapsLockModel, self).__init__()
        self.vocab_size = vocab_size
        self.seq_length = seq_length
        self.weight = nn.Parameter(torch.zeros(seq_length, vocab_size, vocab_size))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        batch_size, seq_length, _ = x.shape
        outputs = []

        for pos in range(min(seq_length, self.seq_length)):
            pos_input = x[:, pos, :]
            pos_weight = self.weight[pos]
            pos_output = torch.matmul(pos_input, pos_weight)
            outputs.append(pos_output.unsqueeze(1))

        return torch.cat(outputs, dim=1)
