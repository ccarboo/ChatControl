import axios from 'axios'

const instance = axios.create({ 
  baseURL: 'https://localhost:8000',
  httpsAgent: { rejectUnauthorized: false },
  withCredentials: true
})

export default instance
