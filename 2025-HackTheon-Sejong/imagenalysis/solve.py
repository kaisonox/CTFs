import requests
from PIL import Image
import numpy as np
import random
import time

# Server URL
URL = "http://hacktheon2025-challs-alb-1807358214.ap-northeast-2.elb.amazonaws.com:9090"

def get_timestamp_cookie():
    """Get the timestamp cookie from the server"""
    response = requests.get(URL)
    cookies = response.cookies
    timestamp = cookies.get('timestamp')
    print(f"Got timestamp cookie: {timestamp}")
    return int(timestamp)

def generate_target_pattern(timestamp):
    """Generate the expected 5x5 pattern based on timestamp"""
    random.seed(timestamp)
    pattern = []
    
    # Get initial bit
    current_bit = random.randint(0, 1)
    pattern.append(current_bit)
    
    # Generate 24 more bits using XOR with next random bit
    for _ in range(24):
        next_random_bit = random.randint(0, 1)
        current_bit = current_bit ^ next_random_bit  # XOR operation
        pattern.append(current_bit)
    
    return pattern

def create_image_from_pattern(pattern):
    """Create a 500x500 PNG image based on the pattern"""
    # Create a blank white image
    img = np.ones((500, 500, 3), dtype=np.uint8) * 255
    
    # Cell size is 100x100 (500/5)
    cell_size = 100
    
    # Fill in the cells based on pattern
    for i in range(5):
        for j in range(5):
            idx = i * 5 + j
            if pattern[idx] == 0:
                # Make cell dark (value <= 32768 or 128 in 8-bit)
                img[i*cell_size:(i+1)*cell_size, j*cell_size:(j+1)*cell_size] = 0
            else:
                # Make cell bright (value > 32768 or 128 in 8-bit)
                img[i*cell_size:(i+1)*cell_size, j*cell_size:(j+1)*cell_size] = 255
    
    # Convert to PIL Image
    pil_img = Image.fromarray(img)
    
    # Save to file
    filename = "valid_image.png"
    pil_img.save(filename)
    print(f"Image saved as {filename}")
    
    return filename

def upload_image(filename, cookies):
    """Upload the image to the server"""
    files = {'imageFile': open(filename, 'rb')}
    response = requests.post(f"{URL}/upload", files=files, cookies=cookies)
    
    print("Server response:")
    print(response.text)
    
    return response

def create_image_for_specific_pattern():
    # The specific pattern provided
    pattern_string = "0100010000100101111111111"
    pattern = [int(bit) for bit in pattern_string]
    
    print(f"Using pattern: {pattern}")
    
    # Create image from pattern
    filename = create_image_from_pattern(pattern)
    
    print(f"Created image with specific pattern for cookie 1752120927")
    return filename

def main():
    # Create image with specific pattern
    filename = create_image_for_specific_pattern()
    
    # Set up session with the specific timestamp cookie
    session = requests.Session()
    session.cookies.set('timestamp', '1752120927')
    
    # Upload image
    response = upload_image(filename, session.cookies)
    
    # Check if we got the correct result
    if "correct" in response.text.lower():
        print("Success! The image was accepted.")
    else:
        print("Failed. The image was rejected.")

if __name__ == "__main__":
    main()
