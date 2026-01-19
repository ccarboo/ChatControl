<script>
import axios from 'axios'
import api from '@/services/api'
    export default{
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                phase: false,
                phase_sign: 0,
                username: '',
                api_id: '',
                api_hash: '',
                phone: '',
                passphrase: '',
                telegram_username: '',
                sms_code: '',
            }
        },
        methods:{
            nextPhase() {
                this.phase = true
            },
            async submitForm() {
                this.errormsg = null
                this.loading = true
                try {
                    const response = await api.post('/signup/step1', {
                        api_id: this.api_id,
                        api_hash: this.api_hash,
                        phone: this.phone,
                        username: this.username,
                        password: this.passphrase
                    })
                    console.log('Signup OK:', response.data)
                } catch (e) {
                    this.errormsg = e.response?.data?.message || e.message
                } finally {
                    this.loading = false
                }
            }
        },
    }
</script>
<template>
    <form @submit.prevent="phase ? submitForm() : nextPhase()">
   
    <div v-show="!phase">
        <div class="mb-3">
            <label for="exampleInputEmail1" class="form-label">API ID</label>
            <input type="text" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="api_id">
        </div>
        <div class="mb-3">
            <label for="exampleInputPassword1" class="form-label">API hash</label>
            <input type="text" class="form-control" id="exampleInputPassword1" v-model="api_hash">
        </div>
        <button type="submit" class="btn btn-primary">Avanti</button>
    </div>

    <div v-show="phase">
        <div class="mb-3">
            <label for="exampleInputPassword1" class="form-label">Phone</label>
            <input type="tel" class="form-control" id="exampleInputPassword1" v-model="phone">
        </div>
        <div class="mb-3">
            <label for="exampleInputPassword1" class="form-label">Username</label>
            <input type="text" class="form-control" id="exampleInputPassword1" v-model="username">
        </div>
        <div class="mb-3">
            <label for="exampleInputPassword1" class="form-label">Passphrase</label>
            <input type="password" class="form-control" id="exampleInputPassword1" v-model="passphrase">
        </div>
        <p v-if="errormsg" class="text-danger">{{ errormsg }}</p>
        <button type="button" class="btn btn-secondary me-2" @click="phase = false">Indietro</button>
        <button type="submit" class="btn btn-primary" :disabled="loading">
            {{ loading ? 'Attendi...' : 'Registrati' }}
        </button>
    </div>

    </form>
</template>