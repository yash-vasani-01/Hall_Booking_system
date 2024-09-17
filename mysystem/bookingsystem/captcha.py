# from PIL import Image
# from captcha.image import ImageCaptcha
# from io import BytesIO


# def generate_captcha() -> list:
#     captchas = []
#     for _ in range(5):  # Generate 5 captchas
#         captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
#         captcha: ImageCaptcha = ImageCaptcha(
#             width=400,
#             height=220,
#             fonts=['C:/Windows/Fonts/arial.ttf'],
#             font_sizes=(40, 50, 60),
#         )
#         data: BytesIO = captcha.generate(captcha_text)
#         image: Image = Image.open(data)
#         captchas.append((image, captcha_text))
#     return captchasfrom PIL import Image

# from PIL import Image
# from captcha.image import ImageCaptcha
# from io import BytesIO

# def generate_captcha() -> tuple:
#     captcha_text = 'Ragunath'  # or you can take input from user also by input()
#     captcha: ImageCaptcha = ImageCaptcha(
#         width=400,
#         height=220,
#         fonts=['C:/Windows/Fonts/arial.ttf'],
#         font_sizes=(40, 50, 60),
#     )
#     data: BytesIO = captcha.generate(captcha_text)
#     image: Image = Image.open(data)
#     return image, captcha_text
import random
import base64
from PIL import Image
from captcha.image import ImageCaptcha
from io import BytesIO

def load_words_from_file(captcha_name: str) -> list:
    """Load words from a text file into a list."""
    with open(captcha_name, 'r') as file:
        words = [line.strip() for line in file]
    return words

def generate_captcha() -> tuple:
    """Generate CAPTCHA using a random word from a file."""
    words = load_words_from_file('words.txt')  # Load words from 'words.txt'
    captcha_text = random.choice(words)  # Select a random word from the file
    
    captcha = ImageCaptcha(
        width=200,
        height=50,
        fonts=['C:/Windows/Fonts/arial.ttf'],  # Ensure this path is correct
        font_sizes=(40, 50, 60),
    )
    
    data = captcha.generate(captcha_text)
    image = Image.open(data)
    
    # Convert the image to base64 for embedding in the response
    buffer = BytesIO()
    image.save(buffer, format='PNG')
    encoded_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return encoded_image, captcha_text

def captcha_image(request):
    """Return the CAPTCHA image stored in the session."""
    encoded_image = request.session.get('captcha_image')
    if encoded_image:
        image = base64.b64decode(encoded_image)
        return HttpResponse(image, content_type='image/png')
    return HttpResponse('Captcha not found', status=404)  # Corrected status code
