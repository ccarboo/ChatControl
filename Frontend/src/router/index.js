import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import sign from '../views/Signup.vue'


const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'login',
      component: Login,
    },
    {
      path: '/signup',
      name: 'signup',
      component: sign
    }
  ],
})

export default router
