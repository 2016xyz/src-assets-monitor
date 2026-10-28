<template>
  <div class="login-page">
    <div class="aurora-light blob-a"></div>
    <div class="aurora-light blob-b"></div>

    <div class="login-wrapper">
      <div class="illustration-pane">
        <div class="brand-badge">
          <span class="pulse-healthy"></span>
          <span>SRC 实时资产雷达系统</span>
        </div>
        <h2 class="hero-headline">持续监控子域名<br><span class="text-grad">解析异动与攻击面</span></h2>
        <p class="hero-subline">高并发 DoH 探针、无感代理池抗封调度、秒级多渠道告警推送。</p>

        <div class="topology-graphic">
          <svg viewBox="0 0 320 220" class="topology-svg">
            <circle cx="160" cy="110" r="28" class="node-root" />
            <circle cx="60" cy="50" r="14" class="node-sub" />
            <circle cx="260" cy="60" r="14" class="node-sub" />
            <circle cx="80" cy="170" r="14" class="node-sub" />
            <circle cx="240" cy="170" r="14" class="node-sub" />
            <line x1="160" y1="110" x2="60" y2="50" class="edge-line" />
            <line x1="160" y1="110" x2="260" y2="60" class="edge-line" />
            <line x1="160" y1="110" x2="80" y2="170" class="edge-line" />
            <line x1="160" y1="110" x2="240" y2="170" class="edge-line" />
          </svg>
        </div>
      </div>

      <div class="login-card">
        <div class="card-top">
          <h3 class="login-title">安全控制台登录</h3>
          <p class="login-desc">请输入管理员凭据以进入系统</p>
        </div>

        <el-alert
          v-if="lockMessage"
          :title="lockMessage"
          type="error"
          show-icon
          :closable="false"
          class="alert-lock"
        />

        <form class="login-form" @submit.prevent="handleLogin">
          <div class="form-item">
            <label>用户名 / 邮箱</label>
            <input v-model="form.username" class="custom-input" placeholder="请输入管理员登录账号" required />
          </div>

          <div class="form-item">
            <label>登录密码</label>
            <input v-model="form.password" type="password" class="custom-input" placeholder="••••••••" required />
          </div>

          <div class="form-item">
            <label>安全计算验证码</label>
            <div class="captcha-row">
              <input v-model="form.captcha_code" class="custom-input captcha-input" placeholder="输入计算结果" required />
              <div class="captcha-img-box" @click="refreshCaptcha" title="点击刷新验证码">
                <span v-html="captchaSvg"></span>
              </div>
            </div>
          </div>

          <button type="submit" class="login-submit-btn" :disabled="loading || !!lockMessage">
            <span v-if="loading" class="spinner"></span>
            <span>{{ loading ? '身份校验中...' : '进入安全控制台' }}</span>
          </button>
        </form>

        <div class="card-footer">
          <span>本系统仅限已授权合法资产检测</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const loading = ref(false)
const lockMessage = ref('')
const captchaSvg = ref('')
const captchaKey = ref('')

const form = ref({
  username: '',
  password: '',
  captcha_code: ''
})

const refreshCaptcha = async () => {
  try {
    const { data } = await axios.post('/api/v1/auth/captcha')
    captchaSvg.value = data.data.svg
    captchaKey.value = data.data.key
  } catch (e) {
    captchaSvg.value = `<svg width="110" height="40"><text x="15" y="26" font-size="18" fill="#3B82F6">6 + 7 = ?</text></svg>`
  }
}

const handleLogin = async () => {
  loading.value = true
  try {
    const { data } = await axios.post('/api/v1/auth/login', {
      ...form.value,
      captcha_key: captchaKey.value
    })
    authStore.setAuth(data.data.token, data.data.user)
    ElMessage.success('身份校验通过')
    
    const target = (route.query.redirect as string) || '/dashboard'
    router.replace(target)
  } catch (err: any) {
    const res = err.response?.data
    if (res?.code === 429) {
      lockMessage.value = res.msg || '多次密码错误，已锁定15分钟'
    } else {
      ElMessage.error(res?.msg || '登录失败，请核对信息')
      refreshCaptcha()
    }
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  refreshCaptcha()
})
</script>

<style scoped>
.login-page {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--grad-bg);
  padding: 24px 16px;
  overflow: hidden;
}

.aurora-light {
  position: absolute;
  border-radius: 50%;
  filter: blur(90px);
  opacity: 0.5;
  pointer-events: none;
}
.blob-a { width: 500px; height: 500px; background: #93C5FD; top: -120px; left: -100px; }
.blob-b { width: 600px; height: 600px; background: #60A5FA; bottom: -200px; right: -120px; }

.login-wrapper {
  position: relative;
  z-index: 10;
  display: flex;
  width: 100%;
  max-width: 960px;
  background: var(--grad-glass);
  backdrop-filter: blur(28px) saturate(180%);
  border: 1px solid var(--border-glass);
  border-radius: var(--r-xl);
  box-shadow: var(--shadow-lg);
  overflow: hidden;
}

.illustration-pane {
  flex: 1.1;
  padding: 48px;
  background: linear-gradient(135deg, rgba(239, 246, 255, 0.7) 0%, rgba(219, 234, 254, 0.4) 100%);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
}
.brand-badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 14px;
  background: rgba(255, 255, 255, 0.8);
  border: 1px solid var(--border-strong);
  border-radius: var(--r-full);
  font-size: 13px;
  font-weight: 500;
  color: var(--brand-700);
  width: fit-content;
  margin-bottom: 24px;
}
.hero-headline {
  font-size: 28px;
  font-weight: 700;
  color: var(--text-1);
  line-height: 1.3;
  margin: 0 0 12px 0;
}
.text-grad {
  background: var(--grad-brand);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.hero-subline { font-size: 14px; color: var(--text-2); line-height: 1.6; margin: 0; }
.topology-graphic { margin-top: auto; padding-top: 32px; }
.topology-svg { width: 100%; height: auto; }
.node-root { fill: var(--brand-500); filter: drop-shadow(0 4px 10px rgba(59,130,246,0.4)); }
.node-sub { fill: #93C5FD; }
.edge-line { stroke: rgba(59, 130, 246, 0.25); stroke-width: 2; stroke-dasharray: 4 2; }

.login-card {
  flex: 1;
  padding: 48px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}
.login-title { font-size: 22px; font-weight: 700; color: var(--text-1); margin: 0 0 6px 0; }
.login-desc { font-size: 13px; color: var(--text-3); margin: 0 0 28px 0; }

.login-form { display: flex; flex-direction: column; gap: 18px; }
.form-item label { display: block; font-size: 13px; font-weight: 500; color: var(--text-2); margin-bottom: 6px; }
.custom-input {
  width: 100%; box-sizing: border-box;
  padding: 11px 14px;
  border-radius: var(--r-sm);
  border: 1px solid var(--border-strong);
  background: rgba(255, 255, 255, 0.9);
  color: var(--text-1);
  font-size: 14px; outline: none;
}
.custom-input:focus { border-color: var(--brand-500); box-shadow: var(--shadow-glow); }
.captcha-row { display: flex; gap: 12px; align-items: center; }
.captcha-img-box {
  width: 120px; height: 42px;
  background: #EFF6FF;
  border: 1px solid var(--border-strong);
  border-radius: var(--r-sm);
  display: flex; align-items: center; justify-content: center;
  cursor: pointer;
}

.login-submit-btn {
  width: 100%;
  padding: 12px;
  background: var(--grad-brand);
  color: #fff;
  border: none;
  border-radius: var(--r-md);
  font-size: 14px; font-weight: 600;
  cursor: pointer;
  box-shadow: var(--shadow-sm);
  margin-top: 8px;
}
.card-footer { margin-top: 24px; text-align: center; font-size: 12px; color: var(--text-3); }

@media (max-width: 768px) {
  .illustration-pane { display: none; }
  .login-card { padding: 32px 20px; }
}
</style>
