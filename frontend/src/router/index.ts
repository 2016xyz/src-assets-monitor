import { createRouter, createWebHistory } from 'vue-router'
import { setupRouterGuard } from './guard'

const routes = [
  {
    path: '/install',
    name: 'Install',
    component: () => import('@/views/install/InstallView.vue'),
    meta: { public: true }
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/auth/LoginView.vue'),
    meta: { public: true }
  },
  {
    path: '/',
    component: () => import('@/layouts/AppLayout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/DashboardView.vue')
      },
      {
        path: 'domains',
        name: 'Domains',
        component: () => import('@/views/domain/DomainListView.vue')
      },
      {
        path: 'proxies',
        name: 'Proxies',
        component: () => import('@/views/proxy/ProxyListView.vue')
      },
      {
        path: 'channels',
        name: 'Channels',
        component: () => import('@/views/notify/NotifyChannelView.vue')
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/setting/SettingView.vue')
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

setupRouterGuard(router)

export default router
