<script>
     export default {
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                username: '',
                password: '',
            }
        },
        methods: {
            async login(){
                
            },
        },
        mounted() {
            // this.refresh()

	    }
    }
</script>
<template>
    <form @submit.prevent="login()">
    <div class="mb-3">
        <label for="exampleInputEmail1" class="form-label">Username</label>
        <input type="text" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp">
    </div>
    <div class="mb-3">
        <label for="exampleInputPassword1" class="form-label">Password</label>
        <input type="password" class="form-control" id="exampleInputPassword1">
    </div>
    
    <button type="submit" class="btn btn-primary">Submit</button>

    <p class="mt-3 text-center">
        Non hai un account?
        <RouterLink to="/signup">Registrati</RouterLink>
    </p>
    </form>
    
</template>