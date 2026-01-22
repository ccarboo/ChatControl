import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Sign from '../views/Signup.vue'
import Home from '../views/Home.vue'

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
      component: Sign
    },
    {
      path:'/home',
      name: 'home',
      component: Home
    },
    {
      path:'/chat/:id',
      name: 'chat',
      component: Home
    }
  ],
})

export default router
