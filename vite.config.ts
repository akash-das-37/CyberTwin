import { defineConfig, build } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { copyFileSync, mkdirSync, existsSync } from 'fs';

function buildContentScript() {
  return {
    name: 'build-content-script',
    apply: 'build',
    async closeBundle() {
      await build({
        configFile: false,
        build: {
          emptyOutDir: false,
          outDir: 'dist',
          lib: {
            entry: resolve(__dirname, 'src/content/contentScript.ts'),
            name: 'CyberTwinContent',
            formats: ['iife'],
            fileName: () => 'content/contentScript.js',
          },
        },
      });
    },
  };
}

function copyManifestPlugin() {
  return {
    name: 'copy-manifest',
    closeBundle() {
      const dist = resolve(__dirname, 'dist');
      mkdirSync(dist, { recursive: true });
      copyFileSync(resolve(__dirname, 'manifest.json'), resolve(dist, 'manifest.json'));
      const iconsDir = resolve(dist, 'icons');
      mkdirSync(iconsDir, { recursive: true });
      for (const size of [16, 32, 48, 128]) {
        const src = resolve(__dirname, `public/icons/icon-${size}.png`);
        if (existsSync(src)) {
          copyFileSync(src, resolve(iconsDir, `icon-${size}.png`));
        }
      }
      const logo = resolve(__dirname, 'public/logo.png');
      if (existsSync(logo)) {
        copyFileSync(logo, resolve(dist, 'logo.png'));
      }
    },
  };
}

export default defineConfig({
  base: './',
  plugins: [react(), buildContentScript(), copyManifestPlugin()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        options: resolve(__dirname, 'options.html'),
        dashboard: resolve(__dirname, 'dashboard.html'),
        background: resolve(__dirname, 'src/background/serviceWorker.ts'),
      },
      output: {
        entryFileNames: (chunk) => {
          if (chunk.name === 'background') return 'background/serviceWorker.js';
          return 'assets/[name].js';
        },
        chunkFileNames: 'assets/chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
