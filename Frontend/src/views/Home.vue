<script>
    import api from '@/services/api'
     export default {
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                chats: [],
                selectedChat: null,
                messaggi: [],
                text: '',
               
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
            async selectChat(chat) {
              this.selectedChat = chat
              this.loading = true
              let response

              try {
                  response = await api.get(`/chats/${chat.id}`, { withCredentials: true })
                  console.log('messaggi ricevuti:', response.data)
                  this.messaggi = response.data.messages
              } catch (e) {
                  this.errormsg = e.response?.data?.message || e.message
              } finally {
                  this.loading = false
              }
            },
            async sendMessage(){
              if (!this.selectedChat || !this.text?.trim()) {
                return
              }
              this.loading = true
              try {
                  await api.post('/messages/send', {
                    text: this.text,
                    chat_id: this.selectedChat.id
                  }, { withCredentials: true })
                  this.text = ''
              } catch (e) {
                  this.errormsg = e.response?.data?.message || e.message
              } finally {
                  this.loading = false
              }
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
                  <img 
                    v-if="chat.cyphered" 
                    src="/lock.svg" 
                    alt="Cifrata" 
                    class="ms-2" 
                    style="width: 16px; height: 16px;"
                  >
                  <img 
                    v-else 
                    src="/unlock.svg" 
                    alt="Non cifrata" 
                    class="ms-2" 
                    style="width: 16px; height: 16px;"
                  >
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
             <div 
               v-for="m in messaggi" 
               :key="m.id" 
               class="message-wrapper"
               :class="{ 'message-out': m.out, 'message-in': !m.out }"
             >
               <div class="message-bubble">
                 <div class="message-header">
                   {{ m.out ? 'Tu' : (m.sender_username || m.sender_id) }}
                 </div>
                 <div class="message-text">{{ m.text }}</div>
                 <div class="message-time">
                   {{ new Date(m.date).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) }}
                 </div>
               </div> 
             </div>
          </div>

          <!-- Input Messaggio -->
            <form @submit.prevent="sendMessage()">
              <div class="p-3 border-top d-flex align-items-center gap-2">
                <input
                  v-model="text"
                  type="text"
                  class="form-control"
                  placeholder="Scrivi un messaggio..."
                >
                <button type="submit" class="btn btn-primary">Invia</button>
              </div>
            </form>
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

/* Stili per i messaggi */
.message-wrapper {
  display: flex;
  margin-bottom: 12px;
}

.message-wrapper.message-out {
  justify-content: flex-end;
}

.message-wrapper.message-in {
  justify-content: flex-start;
}

.message-bubble {
  max-width: 70%;
  padding: 10px 14px;
  border-radius: 18px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  word-wrap: break-word;
}

.message-header {
  font-weight: 600;
  font-size: 0.85rem;
  margin-bottom: 4px;
  color: #7c3aed; /* Viola per distinguere il mittente */
}

.message-out .message-bubble {
  background-color: #0b93f6;
  color: white;
  border-bottom-right-radius: 4px;
}

.message-out .message-header {
  color: #e9d5ff; /* Viola chiaro per contrastare con il blu */
}

.message-in .message-bubble {
  background-color: #e5e5ea;
  color: #000;
  border-bottom-left-radius: 4px;
}

.message-in .message-header {
  color: #6d28d9; /* Viola medio sul fondo chiaro */
}

.message-text {
  margin-bottom: 4px;
  line-height: 1.4;
}

.message-time {
  font-size: 0.75rem;
  opacity: 0.7;
  text-align: right;
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