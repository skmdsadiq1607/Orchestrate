import os

images_dir = "dataset/evidence/images"
pngs = os.listdir(images_dir)
print("PNG files:", pngs)

# Check if pytesseract or easyocr is installed
for tool in ['pytesseract', 'easyocr', 'tesserocr']:
    try:
        __import__(tool)
        print(f"{tool} is installed")
    except ImportError:
        print(f"{tool} is NOT installed")
