from PIL import Image, ImageDraw

def create_icon():
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Outer rounded background (deep dark blue / indigo)
    margin = 12
    draw.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=54,
        fill=(15, 23, 42, 255),  # Slate 900
        outline=(56, 189, 248, 220), # Sky 400
        width=8
    )

    # Concentric tunnel rings (perspective tunnel effect)
    center = (size // 2, size // 2 + 10)
    
    # Ring 1 (outer)
    r1_w, r1_h = 75, 65
    draw.ellipse(
        [center[0] - r1_w, center[1] - r1_h, center[0] + r1_w, center[1] + r1_h],
        outline=(14, 165, 233, 200),
        width=6
    )

    # Ring 2 (middle)
    r2_w, r2_h = 50, 42
    draw.ellipse(
        [center[0] - r2_w, center[1] - r2_h, center[0] + r2_w, center[1] + r2_h],
        outline=(56, 189, 248, 230),
        width=5
    )

    # Ring 3 (inner tunnel portal)
    r3_w, r3_h = 28, 23
    draw.ellipse(
        [center[0] - r3_w, center[1] - r3_h, center[0] + r3_w, center[1] + r3_h],
        fill=(16, 185, 129, 240), # Emerald 500
        outline=(52, 211, 153, 255),
        width=4
    )

    # Lock symbol on top (representing encryption)
    lock_top_y = 50
    # Shackle
    draw.arc(
        [size // 2 - 24, lock_top_y, size // 2 + 24, lock_top_y + 44],
        start=180, end=0,
        fill=(56, 189, 248, 255),
        width=7
    )
    # Shackle legs
    draw.line([size // 2 - 24, lock_top_y + 22, size // 2 - 24, lock_top_y + 36], fill=(56, 189, 248, 255), width=7)
    draw.line([size // 2 + 24, lock_top_y + 22, size // 2 + 24, lock_top_y + 36], fill=(56, 189, 248, 255), width=7)

    # Speed lines radiating into the tunnel
    draw.line([center[0] - 65, center[1], center[0] - 25, center[1]], fill=(56, 189, 248, 180), width=4)
    draw.line([center[0] + 65, center[1], center[0] + 25, center[1]], fill=(56, 189, 248, 180), width=4)

    # Export multiple sizes to .ico
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    icon_images = [img.resize(s, Image.Resampling.LANCZOS) for s in sizes]
    
    img.save("/root/test_project/livekadeh_tunnel/app.ico", format="ICO", sizes=sizes)
    print("app.ico successfully generated with sizes:", sizes)

if __name__ == "__main__":
    create_icon()
