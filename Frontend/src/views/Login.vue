<script>
    import api from '@/services/api'
     export default {
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                sms: '',
                expired: 0,
                username: '',
                password: '',
            }
        },
        methods: {
            async login(){
                this.errormsg = null
                this.loading = true
                let response
                try {
                    response = await api.post('/login', {
                        username: this.username,
                        password: this.password,
                    }, { withCredentials: true })
                    console.log('Signup OK:', response.data)
                } catch (e) {
                    this.errormsg = e.response?.data?.message || e.message
                } finally {
                    this.loading = false
                    console.log('Response status:', response?.data?.status)
                    if (response?.data?.status == "logged in"){
                        this.$router.push('/home')
                    }
                    else{
                        expired = 1
                    }
                }
            },
            async login_expired(){
                this.errormsg = null
                this.loading = true
                let response
                try {
                    response = await api.post('/login/expired', {
                        sms: this.sms,
                    }, { withCredentials: true })
                    console.log('Signup OK:', response.data)
                } catch (e) {
                    this.errormsg = e.response?.data?.message || e.message
                } finally {
                    this.loading = false
                    console.log('Response status:', response?.data?.status)
                    if (response?.data?.status == "logged in"){
                        this.$router.push('/home')
                    }
                    else{
                        expired = 0
                    }
                }
            }
        },
        mounted() {
            // this.refresh()
	    }
    }
</script>
<template>
    <form @submit.prevent="login()">
    <div v-show="expired == 0">
        <div class="mb-3">
            <label for="exampleInputEmail1" class="form-label">Username</label>
            <input type="text" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="username">
        </div>
        <div class="mb-3">
            <label for="exampleInputPassword1" class="form-label">Password</label>
            <input type="password" class="form-control" id="exampleInputPassword1" v-model="password">
        </div>
    </div>
    
    <button type="submit" class="btn btn-primary">{{loading ? 'attendi...' : 'submit' }}</button>
    <div v-show="expired == 0">
        <p class="mt-3 text-center" >
            Non hai un account?
            <RouterLink to="/signup">Registrati</RouterLink>
        </p>
    </div>
    </form>

    <form @submit.prevent="login_expired()">
        <div v-show="expired == 1">
            <div class="mb-3">
                <label for="exampleInputEmail1" class="form-label">SMS</label>
                <input type="text" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" v-model="sms">
            </div>
            <button type="submit" class="btn btn-primary">{{loading ? 'attendi...' : 'submit' }}</button>
        </div>
    </form>
    <p v-if="errormsg" class="text-danger">{{ errormsg }}</p>
</template>