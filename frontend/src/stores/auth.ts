import { defineStore } from 'pinia'
import axios from 'axios'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('src_token') || '',
    user: JSON.parse(localStorage.getItem('src_user') || 'null')
  }),
  actions: {
    setAuth(token: string, user: any) {
      this.token = token
      this.user = user
      localStorage.setItem('src_token', token)
      localStorage.setItem('src_user', JSON.stringify(user))
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    },
    clearAuth() {
      this.token = ''
      this.user = null
      localStorage.removeItem('src_token')
      localStorage.removeItem('src_user')
      delete axios.defaults.headers.common['Authorization']
    }
  }
})
