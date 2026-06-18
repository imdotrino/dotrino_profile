import { defineConfig } from 'vite'

// App interna chica (sin framework): el perfil es un Web Component.
export default defineConfig({
  build: { target: 'es2020' },
})
