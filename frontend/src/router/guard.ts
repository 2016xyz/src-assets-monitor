import type { Router } from 'vue-router'
import axios from 'axios'
import { useAuthStore } from '@/stores/auth'

export function setupRouterGuard(router: Router) {
  let isInstalled: boolean | null = null

  router.beforeEach(async (to, from, next) => {
    // 1. 确认安装状态
    if (isInstalled === null) {
      try {
        const { data } = await axios.get('/api/v1/install/status')
        isInstalled = data?.data?.installed ?? false
      } catch (err: any) {
        if (err.response?.status === 428) {
          isInstalled = false
        } else {
          isInstalled = true
        }
      }
    }

    // 2. 未安装拦截
    if (!isInstalled && to.path !== '/install') {
      return next({ path: '/install' })
    }

    // 3. 已安装封锁
    if (isInstalled && to.path === '/install') {
      return next({ path: '/login' })
    }

    // 4. 登录鉴权守卫
    const authStore = useAuthStore()
    const isPublic = to.meta?.public === true

    if (!isPublic && !authStore.token) {
      return next({ path: '/login', query: { redirect: to.fullPath } })
    }

    next()
  })
}
