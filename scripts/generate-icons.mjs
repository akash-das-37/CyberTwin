/**
 * Generates CyberTwin AI extension icons (red shield on dark background).
 * Run: node scripts/generate-icons.mjs
 */
import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import zlib from 'zlib';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, '..', 'public', 'icons');
const logoPath = join(__dirname, '..', 'public', 'logo.png');

mkdirSync(outDir, { recursive: true });

function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
    }
  }
  return ~c >>> 0;
}

function createPNG(size) {
  const width = size;
  const height = size;
  const raw = Buffer.alloc((width * 4 + 1) * height);
  const cx = width / 2;
  const cy = height / 2;
  const radius = size * 0.42;

  for (let y = 0; y < height; y++) {
    const rowStart = y * (width * 4 + 1) + 1;
    raw[rowStart - 1] = 0;
    for (let x = 0; x < width; x++) {
      const i = rowStart + x * 4;
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const edge = radius;
      const inner = radius * 0.55;

      if (dist <= inner) {
        raw[i] = 220;
        raw[i + 1] = 38;
        raw[i + 2] = 38;
        raw[i + 3] = 255;
      } else if (dist <= edge) {
        const t = (dist - inner) / (edge - inner);
        raw[i] = Math.round(220 * (1 - t) + 15 * t);
        raw[i + 1] = Math.round(38 * (1 - t) + 15 * t);
        raw[i + 2] = Math.round(38 * (1 - t) + 20 * t);
        raw[i + 3] = 255;
      } else if (dist <= edge + 2) {
        raw[i] = 153;
        raw[i + 1] = 27;
        raw[i + 2] = 27;
        raw[i + 3] = Math.round(255 * (1 - (dist - edge) / 2));
      } else {
        raw[i] = 10;
        raw[i + 1] = 10;
        raw[i + 2] = 15;
        raw[i + 3] = 255;
      }
    }
  }

  const compressed = zlib.deflateSync(raw);
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(25);
  ihdr.write('IHDR', 0);
  ihdr.writeUInt32BE(width, 4);
  ihdr.writeUInt32BE(height, 8);
  ihdr[12] = 8;
  ihdr[13] = 6;
  ihdr[14] = 0;
  ihdr[15] = 0;
  ihdr[16] = 0;
  const ihdrCrc = crc32(ihdr.slice(0, 17));
  ihdr.writeUInt32BE(ihdrCrc, 17);

  const idat = Buffer.alloc(compressed.length + 8);
  idat.write('IDAT', 0);
  compressed.copy(idat, 4);
  const idatCrc = crc32(idat.slice(0, compressed.length + 4));
  idat.writeUInt32BE(idatCrc, compressed.length + 4);

  const iend = Buffer.from([0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130]);

  const ihdrLen = Buffer.alloc(4);
  ihdrLen.writeUInt32BE(13, 0);
  const idatLen = Buffer.alloc(4);
  idatLen.writeUInt32BE(compressed.length, 0);

  return Buffer.concat([signature, ihdrLen, ihdr, idatLen, idat, iend]);
}

for (const size of [16, 32, 48, 128]) {
  const png = createPNG(size);
  writeFileSync(join(outDir, `icon-${size}.png`), png);
  console.log(`Created icon-${size}.png`);
}

writeFileSync(logoPath, createPNG(128));
console.log('Created logo.png');
