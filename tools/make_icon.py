# ============================================================================
#  make_icon.py -- draw the application icon for the 3DES file crypto tool
# ---------------------------------------------------------------------------
#  Design: a rounded "app tile" with a blue -> indigo diagonal gradient holding a
#  white padlock (shackle ring + body + keyhole).  A second variant replaces the
#  keyhole with a bold "3" (for a more "3DES"-branded look) so both can be
#  compared before choosing.
#
#  Everything is drawn at 4x supersampling and then downscaled with LANCZOS, so
#  the small sizes (16/24/32 px) stay crisp.
#
#  Outputs (into assets/):
#    icon.ico        multi-size Windows icon (16..256, 32-bit with alpha)
#    icon-256.png    master PNG used in docs / README
#    icon-32.png     small-size preview
#
#  Run: python tools/make_icon.py [--preview DIR]
# ============================================================================

import argparse
import os

from PIL import Image, ImageDraw, ImageFont

# ---------------------------- design constants ----------------------------
C = 1024                      # master canvas edge (px)
SS = 4                        # supersampling factor -> drawn at C*SS
W = C * SS

TILE_MARGIN_R = 0.055         # transparent margin around the tile
TILE_RADIUS_R = 0.225         # tile corner radius

GRAD_TOP = (0x4A, 0x7C, 0xFF)   # #4A7CFF
GRAD_BOT = (0x18, 0x27, 0x66)   # #182766

LOCK_WHITE = (0xFF, 0xFF, 0xFF)
LOCK_SHADE = (0xE6, 0xED, 0xFC)
KEYHOLE = (0x1B, 0x2A, 0x6B)

BODY_W_R = 0.470
BODY_H_R = 0.395
BODY_TOP_R = 0.440
BODY_RADIUS_R = 0.075

RING_OUTER_R = 0.150
RING_STROKE_R = 0.060
RING_CENTER_DY_R = 0.020     # ring center sits slightly below the body top

KEY_CIRCLE_R = 0.048
KEY_CIRCLE_DY_R = 0.145
KEY_STEM_W_R = 0.040
KEY_STEM_DY2_R = 0.258

FONT_CANDIDATES = [
    r'C:\Windows\Fonts\segoeuib.ttf',
    r'C:\Windows\Fonts\arialbd.ttf',
]


def px(r):
    """Design ratio -> supersampled pixels."""
    return int(round(r * W))


def gradient_tile(size):
    """Diagonal gradient (small canvas -> smooth upscale, no numpy needed)."""
    n = 256
    img = Image.new('RGB', (n, n))
    data = []
    for y in range(n):
        for x in range(n):
            t = (x + y) / (2.0 * (n - 1))          # 0 at top-left, 1 at bottom-right
            t = t ** 1.08
            data.append(tuple(
                int(round(GRAD_TOP[i] + (GRAD_BOT[i] - GRAD_TOP[i]) * t)) for i in range(3)))
    img.putdata(data)
    return img.resize((size, size), Image.LANCZOS)


def rounded_mask(size, radius, box):
    """L-mode mask of a rounded rectangle."""
    m = Image.new('L', (size, size), 0)
    ImageDraw.Draw(m).rounded_rectangle(box, radius=radius, fill=255)
    return m


def draw_shackle(layer, cx, cy, outer_r, stroke):
    """White ring (annulus); its lower half is later covered by the lock body."""
    d = ImageDraw.Draw(layer)
    box = [cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r]
    d.ellipse(box, fill=LOCK_WHITE)
    inner = outer_r - stroke
    d.ellipse([cx - inner, cy - inner, cx + inner, cy + inner], fill=(0, 0, 0, 0))


def draw_keyhole(layer, cx, cy, circle_r, stem_w, stem_bottom):
    d = ImageDraw.Draw(layer)
    d.ellipse([cx - circle_r, cy - circle_r, cx + circle_r, cy + circle_r], fill=KEYHOLE)
    d.rounded_rectangle([cx - stem_w // 2, cy, cx + stem_w // 2, stem_bottom],
                        radius=stem_w // 2, fill=KEYHOLE)


def draw_digit(layer, cx, cy, ratio):
    d = ImageDraw.Draw(layer)
    size = px(ratio)
    font = None
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            font = ImageFont.truetype(path, size)
            break
    if font is None:
        return
    d.text((cx, cy), '3', font=font, fill=KEYHOLE, anchor='mm')


def build(variant='lock'):
    """variant: 'lock' (keyhole) or 'three' (bold 3 on the body)."""
    tile_box = [px(TILE_MARGIN_R), px(TILE_MARGIN_R), W - px(TILE_MARGIN_R), W - px(TILE_MARGIN_R)]

    # ---- base tile: gradient clipped by a rounded-rect mask
    base = Image.new('RGBA', (W, W), (0, 0, 0, 0))
    grad = gradient_tile(tile_box[2] - tile_box[0]).convert('RGBA')
    tm = rounded_mask(W, px(TILE_RADIUS_R), tile_box)
    base.paste(grad, (tile_box[0], tile_box[1]), tm.crop(tuple(tile_box)))

    # ---- subtle inner highlight along the top edge (glassy feel)
    hl = Image.new('RGBA', (W, W), (0, 0, 0, 0))
    inset = px(0.020)
    ImageDraw.Draw(hl).rounded_rectangle(
        [tile_box[0] + inset, tile_box[1] + inset, tile_box[2] - inset, tile_box[3] - inset],
        radius=px(TILE_RADIUS_R) - inset, outline=(255, 255, 255, 34), width=px(0.012))
    base = Image.alpha_composite(base, hl)

    # ---- padlock
    lock = Image.new('RGBA', (W, W), (0, 0, 0, 0))
    cx = W // 2
    body_w = px(BODY_W_R)
    body_h = px(BODY_H_R)
    body_top = px(BODY_TOP_R)
    body_box = [cx - body_w // 2, body_top, cx + body_w // 2, body_top + body_h]

    # body: white with a soft bottom shading for a little depth
    body = Image.new('RGBA', (W, W), (0, 0, 0, 0))
    bm = Image.new('L', (W, W), 0)
    ImageDraw.Draw(bm).rounded_rectangle(body_box, radius=px(BODY_RADIUS_R), fill=255)
    shade = Image.new('RGB', (1, 64))
    for i in range(64):
        t = i / 63.0
        shade.putpixel((0, i), tuple(
            int(round(LOCK_WHITE[k] + (LOCK_SHADE[k] - LOCK_WHITE[k]) * t)) for k in range(3)))
    shade = shade.resize((body_w, body_h), Image.BILINEAR).convert('RGBA')
    body_mask = bm.crop(body_box)
    shade = shade.resize(body_mask.size, Image.BILINEAR)
    body.paste(shade, (body_box[0], body_box[1]), body_mask)
    lock = Image.alpha_composite(lock, body)

    # shackle ring: its lower half is masked away by the lock body
    ring = Image.new('RGBA', (W, W), (0, 0, 0, 0))
    draw_shackle(ring, cx, body_top + px(RING_CENTER_DY_R), px(RING_OUTER_R), px(RING_STROKE_R))
    ring = Image.alpha_composite(ring, body)

    lock = Image.alpha_composite(body, ring)

    # keyhole / digit
    detail = Image.new('RGBA', (W, W), (0, 0, 0, 0))
    if variant == 'three':
        draw_digit(detail, cx, body_top + body_h // 2 + px(0.012), 0.255)
    else:
        draw_keyhole(detail, cx, body_top + px(KEY_CIRCLE_DY_R), px(KEY_CIRCLE_R),
                     px(KEY_STEM_W_R), body_top + px(KEY_STEM_DY2_R))
    lock = Image.alpha_composite(lock, detail)
    # keep the padlock strictly inside the tile shape
    lock.putalpha(Image.composite(lock.getchannel('A'), Image.new('L', (W, W), 0), tm))

    out = Image.alpha_composite(base, lock)
    return out.resize((C, C), Image.LANCZOS)


def contact_sheet(images, path):
    """Preview sheet: several sizes of each variant on a neutral background."""
    sizes = [256, 48, 32, 16]
    pad = 24
    cell_h = 256 + 2 * pad
    sheet_w = pad + sum(256 + pad for _ in range(len(sizes))) + pad
    sheet_h = pad + len(images) * (cell_h + pad)
    sheet = Image.new('RGB', (sheet_w, sheet_h), (0x22, 0x24, 0x2A))
    y = pad
    for name, im in images:
        x = pad
        for s in sizes:
            thumb = im.resize((s, s), Image.LANCZOS)
            box_y = y + (256 - s) // 2 if s < 256 else y
            sheet.paste(thumb, (x, box_y), thumb)
            x += 256 + pad
        y += cell_h + pad
    sheet.save(path)
    return sheet.size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--preview', default=None, help='directory for the contact sheet')
    ap.add_argument('--variant', default='lock', choices=['lock', 'three'],
                    help="icon motif: 'lock' = keyhole (default), 'three' = bold 3 on the body")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets = os.path.join(root, 'assets')
    os.makedirs(assets, exist_ok=True)

    primary = build(args.variant)
    alternate = build('three' if args.variant == 'lock' else 'lock')

    ico = os.path.join(assets, 'icon.ico')
    primary.save(ico, format='ICO',
                 sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (40, 40),
                        (32, 32), (24, 24), (20, 20), (16, 16)])
    primary.save(os.path.join(assets, 'icon-256.png'), format='PNG')
    primary.resize((32, 32), Image.LANCZOS).save(os.path.join(assets, 'icon-32.png'), format='PNG')
    alternate.save(os.path.join(assets, 'icon-alt-256.png'), format='PNG')

    print('variant:', args.variant)
    print('written:')
    for f in ('icon.ico', 'icon-256.png', 'icon-32.png', 'icon-alt-256.png'):
        p = os.path.join(assets, f)
        print('  {0:<20} {1} bytes'.format(f, os.path.getsize(p)))

    with Image.open(ico) as im:
        print('ico sizes:', sorted(im.info.get('sizes', [])))

    if args.preview:
        os.makedirs(args.preview, exist_ok=True)
        sheet = os.path.join(args.preview, 'icon_preview.png')
        print('preview sheet:', contact_sheet(
            [('A padlock+keyhole', primary), ('B padlock+3', alternate)], sheet), sheet)


if __name__ == '__main__':
    main()
