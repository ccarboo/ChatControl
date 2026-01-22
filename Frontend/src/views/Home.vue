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
    
</template>