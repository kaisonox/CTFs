import os
from PIL import Image

def process_image(img_path, out_path):
    """
    Reads a 360x360 QR code image with a 4-module quiet zone,
    extracts the 37x37 grid, and writes it to a text file.
    
    Grid format:
    - 37 lines
    - 37 characters per line
    - '1' for filled (black), '0' for unknown/empty (white)
    """
    img = Image.open(img_path).convert('L')
    pixels = img.load()
    
    with open(out_path, 'w') as f:
        for r in range(37):
            line = []
            for c in range(37):
                # The image is 360x360 pixels.
                # 37 modules + 4 modules padding on each side = 45 modules total.
                # 360 pixels / 45 modules = 8 pixels per module.
                # Top-left of the first grid module is at (32, 32).
                # We sample the center of each module (+4 pixels).
                x = 32 + c * 8 + 4
                y = 32 + r * 8 + 4
                
                # Check if the pixel is dark
                if pixels[x, y] < 128:
                    line.append('1')
                else:
                    line.append('0')
            f.write(''.join(line) + '\n')

def main():
    images = ['fake_flag.png', 'real_flag.png']
    for img_name in images:
        if os.path.exists(img_name):
            out_name = img_name.replace('.png', '.txt')
            process_image(img_name, out_name)
            print(f'Successfully created {out_name} from {img_name}')
        else:
            print(f'Image {img_name} not found.')

if __name__ == '__main__':
    main()
