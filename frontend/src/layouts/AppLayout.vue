<template>
  <div class="app-layout">
    <aside class="sidebar-pane">
      <div class="sidebar-logo">
        <div class="brand-square">
          <svg viewBox="0 0 24 24" class="logo-svg" fill="none" stroke="currentColor" stroke-width="1.75">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/>
            <path d="M2 12h20"/>
          </svg>
        </div>
        <div class="brand-text">
          <span class="app-name">SRC 资产雷达</span>
          <span class="app-version">v1.0.0</span>
        </div>
      </div>

      <nav class="nav-menu">
        <router-link to="/dashboard" class="nav-item" active-class="active">
          <span class="nav-icon">📊</span>
          <span class="nav-label">综合仪表盘</span>
          <span class="active-indicator"></span>
        </router-link>

        <router-link to="/domains" class="nav-item" active-class="active">
          <span class="nav-icon">🌐</span>
          <span class="nav-label">资产域名管理</span>
          <span class="active-indicator"></span>
        </router-link>

        <router-link to="/proxies" class="nav-item" active-class="active">
          <span class="nav-icon">🛡️</span>
          <span class="nav-label">网络代理池</span>
          <span class="active-indicator"></span>
        </router-link>

        <router-link to="/channels" class="nav-item" active-class="active">
          <span class="nav-icon">🔔</span>
          <span class="nav-label">告警通知通道</span>
          <span class="active-indicator"></span>
        </router-link>

        <router-link to="/settings" class="nav-item" active-class="active">
          <span class="nav-icon">⚙️</span>
          <span class="nav-label">系统与字典维护</span>
          <span class="active-indicator"></span>
        </router-link>
      </nav>

      <div class="sidebar-bottom">
        <div class="pulse-indicator-row">
          <span class="pulse-healthy"></span>
          <span class="status-tip">DoH 调度网络就绪</span>
        </div>
      </div>
    </aside>

    <div class="main-wrapper">
      <header class="topbar-glass">
        <div class="quick-search-trigger" @click="handleSearchTip">
          <span class="search-ico">🔍</span>
          <span class="placeholder-text">搜索资产域名、解析 IP 或子域...</span>
          <kbd class="kbd-badge">⌘ K</kbd>
        </div>

        <div class="flex-spacer"></div>

        <div class="bell-btn" title="最近告警动态">
          <span class="bell-icon">🔔</span>
          <span class="alarm-badge"></span>
        </div>

        <div class="user-menu-box" @click="handleLogout">
          <div class="avatar-circle">AD</div>
          <span class="user-name">{{ authStore.user?.username || '安全管理员' }}</span>
          <span class="logout-icon" title="安全退出">➔</span>
        </div>
      </header>

      <main class="page-content-outlet">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const handleSearchTip = () => {
  ElMessage.info('快捷键 ⌘K 全局搜索面板调起')
}

const handleLogout = () => {
  authStore.clearAuth()
  ElMessage.success('已安全退出控制台')
  router.push('/login')
}
</script>

<style scoped>
.app-layout { display: flex; min-height: 100vh; background: var(--bg); }
.sidebar-pane {
  width: var(--sidebar-width);
  background: var(--grad-glass);
  backdrop-filter: blur(20px) saturate(180%);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
  position: fixed; top: 0; bottom: 0; left: 0;
  z-index: 20;
}
.sidebar-logo { display: flex; align-items: center; gap: 12px; padding: 24px 20px; }
.brand-square {
  width: 36px; height: 36px; background: var(--grad-brand);
  border-radius: var(--r-sm); display: flex; align-items: center; justify-content: center;
  color: #fff; box-shadow: var(--shadow-sm);
}
.logo-svg { width: 22px; height: 22px; }
.app-name { font-size: 16px; font-weight: 700; color: var(--text-1); }
.app-version { font-size: 11px; color: var(--brand-600); font-weight: 500; margin-left: 6px; }

.nav-menu { display: flex; flex-direction: column; gap: 6px; padding: 12px 14px; }
.nav-item {
  position: relative; display: flex; align-items: center; gap: 12px;
  padding: 10px 14px; border-radius: var(--r-md); color: var(--text-2);
  text-decoration: none; font-size: 13.5px; font-weight: 500; transition: all var(--dur) var(--ease);
}
.nav-item:hover { background: var(--brand-50); color: var(--brand-600); transform: translateX(2px); }
.nav-item.active { background: var(--brand-100); color: var(--brand-700); font-weight: 600; }
.active-indicator {
  display: none; position: absolute; left: 0; top: 8px; bottom: 8px;
  width: 3px; background: var(--brand-500); border-radius: 0 2px 2px 0;
}
.nav-item.active .active-indicator { display: block; }
.sidebar-bottom { margin-top: auto; padding: 20px; border-top: 1px solid var(--border); }
.pulse-indicator-row { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-2); }

.main-wrapper { margin-left: var(--sidebar-width); flex: 1; display: flex; flex-direction: column; }
.topbar-glass {
  height: var(--header-height); background: rgba(255, 255, 255, 0.75);
  backdrop-filter: blur(16px); border-bottom: 1px solid var(--border);
  display: flex; align-items: center; padding: 0 32px;
  position: sticky; top: 0; z-index: 15;
}

.quick-search-trigger {
  display: flex; align-items: center; gap: 10px; background: var(--bg);
  border: 1px solid var(--border-strong); padding: 6px 14px; border-radius: var(--r-md);
  font-size: 13px; color: var(--text-3); cursor: pointer; width: 300px;
}
.quick-search-trigger:hover { background: #fff; border-color: var(--brand-300); }
.kbd-badge { margin-left: auto; font-size: 11px; background: #E2E8F0; color: var(--text-2); padding: 2px 6px; border-radius: 4px; }

.bell-btn { position: relative; font-size: 18px; cursor: pointer; margin-right: 20px; }
.alarm-badge {
  position: absolute; top: -2px; right: -2px; width: 8px; height: 8px;
  background: var(--danger); border-radius: 50%;
}

.user-menu-box {
  display: flex; align-items: center; gap: 10px; cursor: pointer;
  padding: 4px 8px; border-radius: var(--r-md);
}
.user-menu-box:hover { background: var(--brand-50); }
.avatar-circle {
  width: 32px; height: 32px; background: var(--grad-brand); border-radius: 50%;
  color: #fff; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 600;
}
.user-name { font-size: 13px; font-weight: 500; color: var(--text-1); }
.logout-icon { font-size: 14px; color: var(--text-3); }
.flex-spacer { flex: 1; }

.page-content-outlet { padding: 28px 32px; max-width: 1440px; width: 100%; box-sizing: border-box; }

@media (max-width: 1200px) {
  .sidebar-pane { width: var(--sidebar-collapsed-width); }
  .main-wrapper { margin-left: var(--sidebar-collapsed-width); }
  .nav-label, .brand-text, .status-tip { display: none; }
  .quick-search-trigger { width: 200px; }
}

@media (max-width: 768px) {
  .sidebar-pane { display: none; }
  .main-wrapper { margin-left: 0; }
  .quick-search-trigger { display: none; }
  .page-content-outlet { padding: 16px; }
}
</style>
