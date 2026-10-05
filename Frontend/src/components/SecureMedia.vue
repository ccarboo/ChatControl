<template>
  <div class="secure-media-container">
    <div v-if="loading" class="loading-state">
      <span class="spinner">⏳</span> Decifratura in corso...
    </div>

    <div v-else-if="error" class="error-state">
      ❌ Impossibile decifrare il media
    </div>

    <img
      v-else-if="actualMediaType === 'photo'"
      :src="localUrl"
      alt="Foto Sicura"
      class="media-image"
      style="max-width: 100%; max-height: 300px; border-radius: 8px;"
    />

    <video
      v-else-if="actualMediaType === 'video'"
      :src="localUrl"
      controls
      style="max-width: 100%; max-height: 300px; border-radius: 8px;"
    ></video>

    <div v-else class="file-container" @click="downloadDocument" style="cursor: pointer;">
      <img src="/file.svg" alt="file" class="file-icon" style="width: 40px; height: 40px;">
      <div class="file-info">
        <div class="file-name" style="text-decoration: underline; color: #0d6efd;">
          {{ actualFilename }}
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'SecureMedia',
  props: {
    message: { type: Object, required: true },
    chatId: { type: [Number, String], required: true }
  },
  data() {
    return {
      localUrl: null,
      loading: true,
      error: false,
      actualMediaType: 'document',
      actualFilename: 'file_cifrato',
    }
  },
  async mounted() {
    const mime = this.message.mime || this.message.mime_type || '';
    const size = Number(this.message.size) || 0;
    const MAX_INLINE = 10 * 1024 * 1024;
    const inlineOk = (mime.startsWith('image/') || mime.startsWith('video/')) && size <= MAX_INLINE;
    if (inlineOk) {
      await this.loadSecureMedia();
    } else {
      this.actualMediaType = 'document';
      this.actualFilename = this.message.filename || 'file_cifrato';
      this.loading = false;
    }
  },
  beforeUnmount() {
    if (this.localUrl) {
      URL.revokeObjectURL(this.localUrl);
    }
  },
  methods: {
    async loadSecureMedia() {
      try {
        const baseUrl = typeof __API_URL__ !== 'undefined' ? __API_URL__ : 'http://localhost:8000';
        const url = `${baseUrl}/media/secure-download/${this.chatId}/${this.message.id}`;

        const response = await fetch(url, {
          method: 'GET',
          credentials: 'include'
        });

        if (!response.ok) {
          throw new Error("Errore dal server: " + response.status);
        }

        // Legge l'header per capire cosa ha appena decifrato!
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.startsWith('image/')) {
          this.actualMediaType = 'photo';
        } else if (contentType.startsWith('video/')) {
          this.actualMediaType = 'video';
        } else {
          this.actualMediaType = 'document';
        }

        // Estrae il nome originale del file
        const disposition = response.headers.get('Content-Disposition') || '';
        const match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
        if (match) {
          try { this.actualFilename = decodeURIComponent(match[1]); }
          catch {this.actualFilename = match[1];}
        } else if (this.message.filename) {
          this.actualFilename = this.message.filename;
        }

        // Crea l'URL locale nella RAM per mostrarlo
        const blob = await response.blob();
        this.localUrl = URL.createObjectURL(blob);

      } catch (err) {
        console.error("Errore nel download sicuro:", err);
        this.error = true;
      } finally {
        this.loading = false;
      }
    },
    async downloadDocument() {
      let url = this.localUrl;
      let temp = false;
      try {
        if (!url) {
          const baseUrl = typeof __API_URL__ !== 'undefined' ? __API_URL__ : 'http://localhost:8000';
          const r = await fetch(`${baseUrl}/media/cifrato/download/${this.chatId}/${this.message.id}`,
                                { credentials: 'include' });
          if (!r.ok) throw new Error('Download fallito: ' + r.status);
          url = URL.createObjectURL(await r.blob());
          temp = true;
        }
        const a = document.createElement('a');
        a.href = url;
        a.download = this.actualFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      } catch (e) {
        console.error(e);
        this.error = true;
      } finally {
        if (temp && url) URL.revokeObjectURL(url);
      }
    }
  }
}
</script>

<style scoped>
.loading-state, .error-state {
  padding: 8px;
  border-radius: 8px;
  background-color: rgba(0,0,0,0.05);
  font-size: 0.85em;
  color: #666;
}
.error-state { color: #d9534f; background-color: #fdf08a; }
.spinner { display: inline-block; animation: spin 1s linear infinite; }
@keyframes spin { 100% { transform: rotate(360deg); } }
.file-container { display: flex; align-items: center; gap: 8px; }
</style>