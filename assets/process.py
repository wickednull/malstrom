#!/usr/bin/env python3
"""Build the dashboard-ready assets under www/assets/ from the source art.

Source art is layered design-export PNGs (content on a near-white/black
backdrop).  This converts them to clean alpha-keyed, theme-coloured assets
that sit naturally on the dark dashboard.  Run:  python3 assets/process.py
"""

import base64
import io
import os

from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'assets')
OUT = os.path.join(ROOT, 'www', 'assets')


def key_light(img, threshold=245, down=2.2):
    """Near-white background -> transparent; content -> white (soft alpha)."""
    g = img.convert('L')
    alpha = g.point(lambda v: max(0, min(255, int((threshold - v) * down))))
    out = Image.new('RGBA', img.size, (255, 255, 255, 0))
    out.putalpha(alpha)
    return out


def key_dark(img, floor=40, up=4.0, tint=None):
    """Near-black background -> transparent; content keeps colour (bright=opaque)."""
    rgba = img.convert('RGBA')
    r, g, b, _ = rgba.split()
    lum = img.convert('L').point(lambda v: max(0, min(255, int((v - floor) * up))))
    if tint:
        r = Image.new('L', img.size, tint[0])
        g = Image.new('L', img.size, tint[1])
        b = Image.new('L', img.size, tint[2])
    rgba = Image.merge('RGBA', (r, g, b, lum))
    return rgba


def trim(img, pad=8):
    bbox = img.getbbox()
    if bbox:
        bbox = (max(0, bbox[0] - pad), max(0, bbox[1] - pad),
                min(img.width, bbox[2] + pad), min(img.height, bbox[3] + pad))
        img = img.crop(bbox)
    return img


def fit(img, max_w, max_h):
    img.thumbnail((max_w, max_h), Image.LANCZOS)
    return img


def save(img, name):
    os.makedirs(OUT, exist_ok=True)
    img.save(os.path.join(OUT, name), optimize=True)
    print(f'  -> www/assets/{name}  {img.size}  {os.path.getsize(os.path.join(OUT, name))//1024}KB')
    return img


def app_icon():
    """Compose the skull emblem into a square, rounded app tile.

    Produces deploy/malstrom.png (512) and deploy/malstrom.svg (base64-
    embedded 256) — the desktop launcher icon (Icon=malstrom resolves to
    hicolor/scalable/apps/malstrom.svg, installed from deploy/).
    """
    tile = 512
    skull = fit(trim(Image.open(os.path.join(OUT, 'skull.png'))), 480, 480)

    def tile_bg():
        img = Image.new('RGBA', (tile, tile), (9, 9, 12, 255))
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle([2, 2, tile - 2, tile - 2], radius=64,
                               outline=(112, 20, 22, 255), width=3)
        draw.rounded_rectangle([10, 10, tile - 10, tile - 10], radius=56,
                               outline=(200, 10, 14, 60), width=1)
        return img

    bg = tile_bg()

    glow = Image.new('RGBA', (tile, tile), (0, 0, 0, 0))
    d = ImageDraw.Draw(glow)
    d.ellipse([70, 76, tile - 70, tile - 66], fill=(255, 59, 59, 255))
    glow = glow.filter(ImageFilter.GaussianBlur(70))

    shadow = Image.new('RGBA', (tile, tile), (0, 0, 0, 0))
    sw = skull.copy().split()[3].point(lambda v: int(v * 0.6))
    sh = Image.merge('RGBA', (sw, sw, sw, sw))
    shadow.paste(sh, (12, 14), sh)
    shadow = Image.new('RGBA', (tile, tile), (0, 0, 0, 0))
    shadow.paste(sh, (10, 12), sh)
    shadow = shadow.filter(ImageFilter.GaussianBlur(18))

    icon = Image.alpha_composite(bg, glow)
    icon = Image.alpha_composite(icon, shadow)
    icon.alpha_composite(skull,
                         ((tile - skull.width) // 2, (tile - skull.height) // 2 + 6))
    icon = icon.filter(ImageFilter.UnsharpMask(radius=2, percent=80, threshold=2))

    for radius in (0, 0):  # enforce rounded mask on composite
        mask = Image.new('L', (tile, tile), 0)
        ImageDraw.Draw(mask).rounded_rectangle([0, 0, tile - 1, tile - 1],
                                               radius=64, fill=255)
        icon.putalpha(ImageChops.multiply(mask, icon.split()[3]))

    deploy = os.path.join(ROOT, 'deploy')
    png = os.path.join(deploy, 'malstrom.png')
    icon.save(png, optimize=True)
    print(f'  -> deploy/malstrom.png  {icon.size}  '
          f'{os.path.getsize(png)//1024}KB')

    small = icon.copy()
    small.thumbnail((256, 256), Image.LANCZOS)
    buf = io.BytesIO()
    small.save(buf, format='PNG', optimize=True)
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="256" height="256" viewBox="0 0 256 256">
  <image width="256" height="256" xlink:href="data:image/png;base64,{b64}"/>
</svg>'''
    svg_path = os.path.join(deploy, 'malstrom.svg')
    with open(svg_path, 'w', encoding='utf-8') as fh:
        fh.write(svg)
    print(f'  -> deploy/malstrom.svg  {os.path.getsize(svg_path)//1024}KB')


def main():
    print('malstrom-wordmark.png')
    wm = key_light(Image.open(os.path.join(SRC, 'malstrom-wordmark.png')))
    save(fit(trim(wm), 1100, 300), 'wordmark.png')

    print('malstrom-skull-emblem.png')
    sk = key_light(Image.open(os.path.join(SRC, 'malstrom-skull-emblem.png')))
    skull = fit(trim(sk), 800, 800)
    save(skull, 'skull.png')
    save(fit(trim(sk), 64, 64), 'favicon.png')

    print('malstrom-ui-accents.png')
    ac = key_light(Image.open(os.path.join(SRC, 'malstrom-ui-accents.png')))
    save(fit(trim(ac), 1400, 520), 'accents.png')

    print('logo.jpeg')
    lg = key_dark(Image.open(os.path.join(SRC, 'logo.jpeg')),
                  tint=(200, 10, 14))
    save(fit(trim(lg), 1200, 420), 'logo.png')

    print('malstrom-background.png')
    bg = Image.open(os.path.join(SRC, 'malstrom-background.png')).convert('RGB')
    bg = ImageEnhance.Brightness(bg).enhance(0.92)
    bg = ImageEnhance.Contrast(bg).enhance(1.04)
    save(fit(bg, 1600, 900), 'bg.jpg')

    print('app icon')
    app_icon()


if __name__ == '__main__':
    main()