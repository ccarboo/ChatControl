import axios from "axios";

const instance = axios.create({
	baseURL: __API_URL__,
	timeout: 1000 * 5
});
axios.defaults.withCredentials = true; 
app.config.globalProperties.$axios = axios;

export default instance;