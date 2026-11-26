import struct, zlib

def make_png(width, height, rgb_func, filename):
    raw_data = bytearray()
    for y in range(height):
        raw_data.append(0) # filter byte: none
        for x in range(width):
            r, g, b = rgb_func(x, y, width, height)
            raw_data.extend((r, g, b))

    compressed = zlib.compress(raw_data, 9)

    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)

    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
    png += chunk(b'IDAT', compressed)
    png += chunk(b'IEND', b'')

    with open(filename, 'wb') as f:
        f.write(png)

def gradient(x, y, w, h):
    dx1 = (x - w*0.25) / w
    dy1 = (y - h*0.25) / h
    dist1 = (dx1*dx1 + dy1*dy1) ** 0.5
    glow1 = max(0.0, 1.0 - dist1 * 1.8)

    dx2 = (x - w*0.75) / w
    dy2 = (y - h*0.75) / h
    dist2 = (dx2*dx2 + dy2*dy2) ** 0.5
    glow2 = max(0.0, 1.0 - dist2 * 1.8)

    r = int(7 + glow1 * 60)
    g = int(8 + glow1 * 50 + glow2 * 70)
    b = int(15 + glow1 * 140 + glow2 * 100)
    return (min(255, r), min(255, g), min(255, b))

if __name__ == '__main__':
    make_png(1200, 630, gradient, 'frontend/public/og-image.png')
    print("og-image.png generated successfully")
