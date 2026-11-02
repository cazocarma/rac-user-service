"""Generate synthetic OCR fixtures; font bytes are never copied to the repo.

Run with Pillow and --font pointing at a locally licensed TrueType font.
Tests read the committed PNGs and do not require Pillow or a system font.
"""
import argparse
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

parser=argparse.ArgumentParser()
parser.add_argument('--font',required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parent
font=ImageFont.truetype(args.font,48)
for filename,text in (
    ('contact_border.png','CONTACTO +56 9 1234 5678'),
    ('benign.png','CINE Y MUSEOS'),
):
    image=Image.new('RGB',(1200,400),'white')
    ImageDraw.Draw(image).text((12,24),text,font=font,fill='black')
    path=root/filename
    image.save(path)
    # Synthetic private trailing metadata must disappear from normalized output.
    with path.open('ab') as output:
        output.write(b'RAC-SYNTHETIC-PRIVATE-METADATA')
