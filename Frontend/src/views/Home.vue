<script>
    import api from '@/services/api'
     export default {
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                file: null,
                chats: [],
                selectedChat: null,
                messaggi: [],
                text: '',
                useAltSend: false,
                chatsInterval: null,
                chatReloadInterval: null
            }
        },
        methods: {
            removeFile() {
              this.file = null;
              this.$refs.fileInput.value = '';
            },
            handleFileChange(event) {
              this.file = event.target.files[0];
            },
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
                  
                  await this.init_chat(chat)
                  this.scrollToBottom()
              } catch (e) {
                  this.errormsg = e.response?.data?.message || e.message
              } finally {
                  this.loading = false
              }
            },
            async reload_chat(){
              this.loading = true
              let response
              let chat = this.selectedChat
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
              if (!this.selectedChat) {
                return
              }
              this.loading = true
              try {
                if(this.file && this.text){

                  const formData = new FormData()
                  formData.append('file',this.file)
                  formData.append('text', this.text)
                  formData.append('chat_id',this.selectedChat.id)
                  formData.append('cryph',false)
                  formData.append('group',this.selectedChat.is_group)
                  await api.post('/messages/send/file', formData,
                   { withCredentials: true , headers: { 'Content-Type': 'multipart/form-data' }})
                  
                }
                if(this.file && !this.text){
                  const formData = new FormData()
                  formData.append('file',this.file)
                  formData.append('text', '')
                  formData.append('chat_id',this.selectedChat.id)
                  formData.append('cryph',false)
                  formData.append('group',this.selectedChat.is_group)

                  await api.post('/messages/send/file', formData,
                   { withCredentials: true , headers: { 'Content-Type': 'multipart/form-data' }})
                }
                else{
                  await api.post('/messages/send', {
                    text: this.text,
                    chat_id: this.selectedChat.id,
                    cryph: false,
                    group: this.selectedChat.is_group
                  }, { withCredentials: true })
                  
                }
              } catch (e) {
                  this.errormsg = e.response?.data?.message || e.message
              } finally {
                  this.file = null
                  this.$refs.fileInput.value = '';
                  this.loading = false
                  this.text = ''
                  await this.reload_chat()
              }
            },
            async handleSubmit(){
              if (this.useAltSend) {
                await this.sendChyp()
              } else {
                await this.sendMessage()
              }
            },
            async sendChyp(){
              if (!this.selectedChat) {
                return
              }
              this.loading = true
              if (!this.file){
                try {
                    await api.post('/messages/send', {
                      text: this.text,
                      chat_id: this.selectedChat.id,
                      cryph: true,
                      group: this.selectedChat.is_group
                    }, { withCredentials: true })
                    this.text = ''
                    await this.reload_chat()
                } catch (e) {
                    this.errormsg = e.response?.data?.message || e.message
                } finally {
                    this.loading = false
                }
              }
              else{
                if(this.file && this.text){

                  const formData = new FormData()
                  formData.append('file',this.file)
                  formData.append('text', this.text)
                  formData.append('chat_id',this.selectedChat.id)
                  formData.append('cryph',true)
                  formData.append('group',this.selectedChat.is_group)
                  try{
                    await api.post('/messages/send/file', formData,
                    { withCredentials: true , headers: { 'Content-Type': 'multipart/form-data' }})
                  }
                  catch(e){
                    this.errormsg = e.response?.data?.message || e.message
                  }
                  finally{
                    this.file = null
                    this.$refs.fileInput.value = '';
                    this.loading = false
                    this.text = ''
                    await this.reload_chat()
                  }
                }
                else if(this.file && !this.text){

                  const formData = new FormData()
                  formData.append('file',this.file)
                  formData.append('text', "")
                  formData.append('chat_id',this.selectedChat.id)
                  formData.append('cryph',true)
                  formData.append('group',this.selectedChat.is_group)
                  try{
                    await api.post('/messages/send/file', formData,
                    { withCredentials: true , headers: { 'Content-Type': 'multipart/form-data' }})
                  }
                  catch(e){
                    this.errormsg = e.response?.data?.message || e.message
                  }
                  finally{
                    this.file = null
                    this.$refs.fileInput.value = '';
                    this.loading = false
                    this.text = ''
                    await this.reload_chat()
                  }
                }
              }
            },
            async sendkey(){
              if (!this.selectedChat) {
                return
              }
              this.loading = true
              try {
                  await api.post('/messages/initializing', {
                    chat_id: this.selectedChat.id
                  }, { withCredentials: true })
                  await this.reload_chat()
              } catch (e) {
                  this.errormsg = e.response?.data?.message || e.message
              } finally {
                  this.loading = false
              }
            },
            async init_chat(chat){
              let response
              try {
                  response = await api.get(`/chats/${chat.id}/inits`, { withCredentials: true })
                  console.log('init chat:', response.data)
              } catch (e) {
                  console.error('Errore init chat:', e)
              }
            },
            scrollToBottom() {
              this.$nextTick(() => {
                const messagesDiv = this.$refs.messagesContainer
                if (messagesDiv) {
                  messagesDiv.scrollTop = messagesDiv.scrollHeight
                }
              })
            },
            formatFileSize(bytes) {
              if (!bytes) return '0 B'
              const k = 1024
              if (bytes < k) return bytes + ' B'
              if (bytes < k * k) return (bytes / k).toFixed(1) + ' KB'
              if (bytes < k * k * k) return (bytes / (k * k)).toFixed(1) + ' MB'
              return (bytes / (k * k * k)).toFixed(1) + ' GB'
            },
            handleFileClick(message) {
              console.log('File clicked:', message)
            }
        },
        mounted() {
            this.get_chats()
            this.chatsInterval = setInterval(() => {
                this.get_chats()
            }, 20000)
            this.chatReloadInterval = setInterval(() => {
                if (this.selectedChat) {
                    this.reload_chat()
                }
            }, 5000)
        },
        beforeUnmount() {
            if (this.chatsInterval) clearInterval(this.chatsInterval)
            if (this.chatReloadInterval) clearInterval(this.chatReloadInterval)
        }
    }
</script>
<template>
    <div class="container-fluid vh-100">
    <div class="row h-100">
      
      <div class="col-md-4 col-lg-3 border-end p-0 bg-light d-flex flex-column h-100">
        <div class="p-3 border-bottom bg-white">
          <h5 class="mb-0">Le mie Chat</h5>
        </div>

        <div class="list-group list-group-flush overflow-auto flex-grow-1">
          <button 
            v-for="chat in chats" 
            :key="chat.id"
            @click="selectChat(chat)"
            class="list-group-item list-group-item-action py-3 border-0"
            :class="{ 'active-chat': selectedChat && selectedChat.id === chat.id }"
          >
            <div class="d-flex align-items-center">
              <div class="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center flex-shrink-0" style="width: 45px; height: 45px;">
                {{ chat.name.charAt(0) }}
              </div>
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

      <div class="col-md-8 col-lg-9 p-0 d-flex flex-column h-100 bg-white">
        <div v-if="selectedChat" class="d-flex flex-column h-100">
          <div class="p-3 border-bottom d-flex align-items-center justify-content-between bg-light">
            <strong>{{ selectedChat.name }}</strong>
            <button @click="sendkey()" class="btn btn-primary btn-sm">Invia chiave</button>
          </div>
          
          <div ref="messagesContainer" class="flex-grow-1 overflow-auto p-3 bg-chat">
             <div 
               v-for="m in messaggi" 
               :key="m.id" 
               class="message-wrapper"
               :class="{ 'message-out': m.out, 'message-in': !m.out }"
             >
               <div class="message-bubble">
                 <div class="message-header" >
                   {{ m.out ? 'Tu' : (m.sender_username || m.sender_id) }}
                 </div>
                 <div v-if="m.file">
                   <div class="file-container" @click="handleFileClick(m)">
                     <img src="/file.svg" alt="file" class="file-icon">
                     <div class="file-info">
                       <div class="file-name">{{ m.filename }}</div>
                       <div class="file-size">{{ formatFileSize(m.size) }}</div>
                     </div>
                   </div>
                 </div>
                 <div class="message-text" v-if="!m.error">
                    {{ m.text }}
                  </div>
                  <div class="message-text" v-else>
                      messaggio compromesso!!
                  </div>
                 <div class="message-time">
                   {{ new Date(m.date).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) }}
                 </div>
               </div> 
             </div>
          </div>

            <form @submit.prevent="handleSubmit()">
              <div class="p-3 border-top d-flex align-items-center gap-2">
                <input
                  v-model="text"
                  type="text"
                  class="form-control"
                  placeholder="Scrivi un messaggio..."
                >
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" id="altSend" v-model="useAltSend">
                  <label class="form-check-label" for="altSend">cifra</label>
                </div>
                <button type="submit" class="btn btn-primary send-btn">
                  <img 
                    src="/send.svg"  
                    alt="Invia"
                    class="send-icon"
                  >
                </button>
                <input
                  ref="fileInput"
                  type="file"
                  style="display: none"
                  @change="handleFileChange"
                />
                <button type="button" class="btn btn-primary send-btn" @click="$refs.fileInput.click()">
                  <img src="/paperclip.svg" alt="Allega" class="send-icon" />
                </button>
                <button v-if="file" type="button" class="btn btn-danger" @click="removeFile">
                  Rimuovi file
                </button>
              </div>  
            </form>
        </div>

        <div v-else class="btn btn-primary h-100 d-flex align-items-center justify-content-center bg-light text-muted">
          Seleziona una chat per iniziare a messaggiare
        </div>
      </div>

    </div>
  </div>
</template>

<style scoped>
.vh-100 { height: 100vh; overflow: hidden; }


.active-chat {
  background-color: #e9ecef ; 
  border-left: 4px solid #198754 ; 
}


.bg-chat {
  background-color: #f8f9fa;
}

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
  color: #7c3aed; 
}

.message-out .message-bubble {
  background-color: #0b93f6;
  color: white;
  border-bottom-right-radius: 4px;
}

.message-out .message-header {
  color: #e9d5ff; 
}

.message-in .message-bubble {
  background-color: #e5e5ea;
  color: #000;
  border-bottom-left-radius: 4px;
}

.message-in .message-header {
  color: #6d28d9; 
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

.overflow-auto::-webkit-scrollbar {
  width: 5px;
}
.overflow-auto::-webkit-scrollbar-thumb {
  background: #ccc;
  border-radius: 10px;
}

/* Bottone invio quadrato e icona centrata */
.send-btn {
  width: 40px;
  height: 40px;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
}
.send-icon {
  width: 22px;
  height: 22px;
  display: block;
  margin: auto;
}

/* File display */
.file-container {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px;
  background-color: rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  margin-bottom: 6px;
}

.file-icon {
  width: 40px;
  height: 40px;
  flex-shrink: 0;
}

.file-info {
  flex-grow: 1;
  min-width: 0;
}

.file-name {
  font-weight: 600;
  font-size: 0.9rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-size {
  font-size: 0.75rem;
  opacity: 0.8;
  margin-top: 2px;
}

</style>