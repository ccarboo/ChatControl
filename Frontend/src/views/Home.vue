<script>
    import api from '@/services/api'
     export default {
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                chats: [],
               
            }
        },
        methods: {
            async get_chats(){
                this.errormsg = null
                this.loading = true
                let response
                try {
                    response = await api.get('/chats', { withCredentials: true })
                    console.log('chat requested:', response.data)
                    this.chats = response.data.chats
                } catch (e) {
                    this.errormsg = e.response?.data?.message || e.message
                } finally {
                    this.loading = false
                }
            },
            open_chat(chatId) {
                this.$router.push({ name: 'chat', params: { id: chatId } })
            }
        },
        mounted() {
            this.get_chats()
	    }
    }
</script>
<template>
    <div class="container-fluid vh-100">
    <div class="row h-100">
      
      <!-- SIDEBAR SINISTRA (Lista Chat) -->
      <div class="col-md-4 col-lg-3 border-end p-0 bg-light d-flex flex-column h-100">
        <!-- Header della Sidebar (es. il tuo profilo o cerca) -->
        <div class="p-3 border-bottom bg-white">
          <h5 class="mb-0">Le mie Chat</h5>
        </div>

        <!-- Lista Chat scrollabile -->
        <div class="list-group list-group-flush overflow-auto flex-grow-1">
          <button 
            v-for="chat in chats" 
            :key="chat.id"
            @click="selectChat(chat)"
            class="list-group-item list-group-item-action py-3 border-0"
            :class="{ 'active-chat': selectedChat && selectedChat.id === chat.id }"
          >
            <div class="d-flex align-items-center">
              <!-- Avatar -->
              <div class="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center flex-shrink-0" style="width: 45px; height: 45px;">
                {{ chat.name.charAt(0) }}
              </div>
              <!-- Info Chat -->
              <div class="ms-3 overflow-hidden">
                <div class="d-flex justify-content-between align-items-center">
                  <strong class="text-truncate">{{ chat.name }}</strong>
                  <i v-if="chat.is_encrypted" class="bi bi-lock-fill text-success small ms-2"></i>
                </div>
                <div class="small text-muted text-truncate">{{ chat.last_msg }}</div>
              </div>
            </div>
          </button>
        </div>
      </div>

      <!-- AREA MESSAGGI DESTRA -->
      <div class="col-md-8 col-lg-9 p-0 d-flex flex-column h-100 bg-white">
        <div v-if="selectedChat" class="d-flex flex-column h-100">
          <!-- Header Chat Attiva -->
          <div class="p-3 border-bottom d-flex align-items-center bg-light">
            <strong>{{ selectedChat.name }}</strong>
          </div>
          
          <!-- Area Messaggi (qui andrà il tuo componente messaggi) -->
          <div class="flex-grow-1 overflow-auto p-3 bg-chat">
             <!-- v-for messaggi qui -->
             <p v-for="m in messaggi" :key="m.id">{{ m.text }}</p>
          </div>

          <!-- Input Messaggio -->
          <div class="p-3 border-top">
            <input type="text" class="form-control" placeholder="Scrivi un messaggio...">
          </div>
        </div>

        <!-- Schermata di benvenuto se nessuna chat è selezionata -->
        <div v-else class="h-100 d-flex align-items-center justify-content-center bg-light text-muted">
          Seleziona una chat per iniziare a messaggiare
        </div>
      </div>

    </div>
  </div>
</template>

<style scoped>
/* Forza l'altezza a tutto scherm senza scroll della pagina principale */
.vh-100 { height: 100vh; overflow: hidden; }

/* Colore per la chat selezionata (personalizzato invece del blu di Bootstrap) */
.active-chat {
  background-color: #e9ecef ; /* Grigio chiaro */
  border-left: 4px solid #198754 ; /* Linea verde per indicare sicurezza */
}

/* Sfondo area messaggi (opzionale) */
.bg-chat {
  background-color: #f8f9fa;
}

/* Nascondi la scrollbar ma permetti lo scroll (opzionale per estetica) */
.overflow-auto::-webkit-scrollbar {
  width: 5px;
}
.overflow-auto::-webkit-scrollbar-thumb {
  background: #ccc;
  border-radius: 10px;
}

</style>