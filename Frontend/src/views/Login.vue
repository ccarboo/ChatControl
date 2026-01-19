<script>
     export default {
        data: function() {
            return {
                errormsg: null,
                loading: false,
                some_data: null,

                username: '',
            }
        },
        methods: {
            async refresh() {

                this.loading = true;
                this.errormsg = null;
                try {
                    let response = await this.$axios.get("/");
                    this.some_data = response.data;
                } catch (e) {
                    this.errormsg = e.toString();
                }
                this.loading = false;
            },
            async login(){
                try {
                    
                    let response = await this.$axios.post("/user", {username: this.username});
                
                    sessionStorage.setItem("authorization", response.data)
                    this.$emit("login-success")
                    this.$router.push("/home")
                    
                   
                } catch (e) {
                    this.errormsg = e.toString();
                }
            },
        },
        mounted() {
            // this.refresh()

	    }
    }
</script>
<template>
    <form>
    <div class="mb-3">
        <label for="exampleInputEmail1" class="form-label">Email address</label>
        <input type="email" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp">
        <div id="emailHelp" class="form-text">We'll never share your email with anyone else.</div>
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