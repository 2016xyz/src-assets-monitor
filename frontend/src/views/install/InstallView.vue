<template>
  <div class="install-container">
    <div class="aurora-blob blob-1"></div>
    <div class="aurora-blob blob-2"></div>
    <div class="aurora-blob blob-3"></div>

    <div class="install-glass-card">
      <div class="install-header">
        <div class="logo-box">
          <svg class="radar-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75">
            <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z"/>
            <path d="M12 6a6 6 0 1 0 6 6 6 6 0 0 0-6-6zm0 8a2 2 0 1 1 2-2 2 2 0 0 1-2 2z"/>
            <path d="m14 14 5 5"/>
          </svg>
        </div>
        <h1 class="brand-title">SRC 资产检测站</h1>
        <p class="brand-subtitle">首次系统自动化部署向导</p>
      </div>

      <!-- 步骤条 -->
      <div class="steps-wrapper desktop-steps">
        <div 
          v-for="(st, idx) in steps" 
          :key="st.key" 
          class="step-item"
          :class="{ active: currentStep === idx + 1, completed: currentStep > idx + 1 }"
        >
          <div class="step-circle">
            <span v-if="currentStep > idx + 1">✓</span>
            <span v-else>{{ idx + 1 }}</span>
          </div>
          <span class="step-title">{{ st.title }}</span>
          <div v-if="idx < steps.length - 1" class="step-line"></div>
        </div>
      </div>

      <!-- 移动端简洁进度 -->
      <div class="mobile-steps-bar">
        <span>步骤 {{ currentStep }} / {{ steps.length }} · {{ steps[currentStep - 1].title }}</span>
        <div class="progress-track">
          <div class="progress-fill" :style="{ width: `${(currentStep / steps.length) * 100}%` }"></div>
        </div>
      </div>

      <!-- 内容卡片 -->
      <div class="step-content-box">
        <!-- 步骤 1: 环境自检 -->
        <div v-if="currentStep === 1" class="step-pane">
          <h3 class="pane-title">运行时环境与依赖自检</h3>
          <div class="env-list">
            <div class="env-item">
              <span class="env-label">PHP 运行时 ({{ envData.php_version?.current || '...' }})</span>
              <span class="soft-tag" :class="envData.php_version?.status">
                {{ envData.php_version?.status === 'pass' ? '通过' : '不兼容' }}
              </span>
            </div>
            <div v-for="ext in envData.extensions" :key="ext.name" class="env-item">
              <div class="env-meta">
                <span class="env-label">{{ ext.name }}</span>
                <span class="env-desc">{{ ext.description }}</span>
              </div>
              <span class="soft-tag" :class="ext.status">
                {{ ext.status === 'pass' ? '支持' : (ext.status === 'warn' ? '兼容模式' : '缺失') }}
              </span>
            </div>
            <div v-for="perm in envData.permissions" :key="perm.path" class="env-item">
              <span class="env-label">{{ perm.path }}</span>
              <span class="soft-tag" :class="perm.status">
                {{ perm.status === 'pass' ? '可写' : '只读' }}
              </span>
            </div>
          </div>
        </div>

        <!-- 步骤 2: 数据库设置 (地址、端口、数据库名、连接账号、密码全部独立输入) -->
        <div v-if="currentStep === 2" class="step-pane">
          <h3 class="pane-title">MySQL 数据库设置</h3>
          <div class="form-grid">
            <div class="form-group">
              <label>数据库服务器地址 (Host)</label>
              <input v-model="dbForm.host" placeholder="127.0.0.1" class="input-theme" />
            </div>
            <div class="form-group">
              <label>端口 (Port)</label>
              <input v-model.number="dbForm.port" type="number" placeholder="3306" class="input-theme" />
            </div>
            <div class="form-group col-span-2">
              <label>数据库名称 (Database Name)</label>
              <input v-model="dbForm.database" placeholder="src_monitor" class="input-theme" />
            </div>
            <div class="form-group">
              <label>数据库连接账号 (Username)</label>
              <input v-model="dbForm.username" placeholder="root" class="input-theme" />
            </div>
            <div class="form-group">
              <label>数据库连接密码 (Password)</label>
              <input v-model="dbForm.password" type="password" placeholder="请输入数据库连接密码" class="input-theme" />
            </div>
            <div class="form-group col-span-2 checkbox-group">
              <label class="checkbox-label">
                <input v-model="dbForm.auto_create" type="checkbox" />
                <span>若数据库不存在则自动创建</span>
              </label>
              <button class="ghost-btn-sm" :disabled="testingDb" @click="handleTestDb">
                {{ testingDb ? '连通性测试中...' : '测试数据库连接' }}
              </button>
            </div>
          </div>
        </div>

        <!-- 步骤 3: 管理员账号 -->
        <div v-if="currentStep === 3" class="step-pane">
          <h3 class="pane-title">设置系统管理账户</h3>
          <div class="form-grid">
            <div class="form-group col-span-2">
              <label>管理员登录名</label>
              <input v-model="adminForm.username" placeholder="admin" class="input-theme" />
            </div>
            <div class="form-group col-span-2">
              <label>管理员邮箱</label>
              <input v-model="adminForm.email" type="email" placeholder="security@company.com" class="input-theme" />
            </div>
            <div class="form-group">
              <label>登录密码 (需含大小写与数字)</label>
              <input v-model="adminForm.password" type="password" placeholder="••••••••" class="input-theme" />
            </div>
            <div class="form-group">
              <label>确认新密码</label>
              <input v-model="adminForm.password_confirmation" type="password" placeholder="••••••••" class="input-theme" />
            </div>
          </div>
        </div>

        <!-- 步骤 4: 告警通道 -->
        <div v-if="currentStep === 4" class="step-pane">
          <h3 class="pane-title">初始通知渠道 (可选)</h3>
          <div class="form-group">
            <label>企业微信机器人 Webhook 地址</label>
            <input v-model="wecomWebhook" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." class="input-theme" />
          </div>
          <div class="channel-hint">
            提示：更多通知渠道（邮件/钉钉/飞书）可在系统设置中随时拓展。
          </div>
        </div>

        <!-- 步骤 5: 完成部署 -->
        <div v-if="currentStep === 5" class="step-pane text-center">
          <div class="success-badge">✓</div>
          <h3 class="pane-title">系统初始化配置完成！</h3>
          <p class="summary-text">
            数据库架构已迁移导入，系统已写入 <code>install.lock</code> 永久固化安装入口。
          </p>
          <div class="security-banner">
            <strong>安全运维忠告：</strong> 建议在生产环境 Nginx 中屏蔽 <code>/install</code> 路由，并启用 HTTPS 安全加密。
          </div>
        </div>
      </div>

      <!-- 底部操作按钮 -->
      <div class="install-footer">
        <button v-if="currentStep > 1 && currentStep < 5" class="ghost-btn" @click="currentStep--">
          上一步
        </button>
        <div class="flex-spacer"></div>
        <button 
          v-if="currentStep < 5" 
          class="primary-btn" 
          :disabled="loading || (currentStep === 1 && !envData.can_proceed)"
          @click="handleNext"
        >
          <span v-if="loading" class="spinner"></span>
          <span>{{ currentStep === 4 ? '执行系统安装' : '下一步' }}</span>
        </button>
        <button v-else class="primary-btn" @click="goToDashboard">
          进入安全控制台 →
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { ElMessage } from 'element-plus'

const router = useRouter()
const currentStep = ref(1)
const loading = ref(false)
const testingDb = ref(false)
const installToken = ref('')

const steps = [
  { key: 'env', title: '环境自检' },
  { key: 'db', title: '数据库' },
  { key: 'admin', title: '管理员' },
  { key: 'notify', title: '告警通道' },
  { key: 'finish', title: '完成部署' }
]

const envData = ref<any>({ can_proceed: true, extensions: [], permissions: [] })

const dbForm = ref({
  host: '127.0.0.1',
  port: 3306,
  database: 'src_monitor',
  username: 'root',
  password: '',
  auto_create: true
})

const adminForm = ref({
  username: 'admin',
  email: '',
  password: '',
  password_confirmation: ''
})

const wecomWebhook = ref('')

onMounted(async () => {
  try {
    const { data } = await axios.get('/api/v1/install/status')
    if (data.data?.installed) {
      router.replace('/login')
      return
    }
    installToken.value = data.data.install_token
    fetchEnvCheck()
  } catch (e: any) {
    ElMessage.error('无法初始化安装流程')
  }
})

const fetchEnvCheck = async () => {
  try {
    const { data } = await axios.post('/api/v1/install/check-env', {}, {
      headers: { 'X-Install-Token': installToken.value }
    })
    envData.value = data.data
  } catch (err: any) {
    ElMessage.error(err.response?.data?.msg || '环境检查失败')
  }
}

const handleTestDb = async () => {
  testingDb.value = true
  try {
    const { data } = await axios.post('/api/v1/install/test-db', dbForm.value, {
      headers: { 'X-Install-Token': installToken.value }
    })
    ElMessage.success(data.msg)
  } catch (err: any) {
    ElMessage.error(err.response?.data?.msg || '数据库连接失败')
  } finally {
    testingDb.value = false
  }
}

const handleNext = async () => {
  loading.value = true
  try {
    if (currentStep.value === 1) {
      currentStep.value = 2
    } else if (currentStep.value === 2) {
      await axios.post('/api/v1/install/database', dbForm.value, {
        headers: { 'X-Install-Token': installToken.value }
      })
      currentStep.value = 3
    } else if (currentStep.value === 3) {
      await axios.post('/api/v1/install/admin', adminForm.value, {
        headers: { 'X-Install-Token': installToken.value }
      })
      currentStep.value = 4
    } else if (currentStep.value === 4) {
      const channels = []
      if (wecomWebhook.value.trim()) {
        channels.push({
          name: '企业微信群机器人',
          type: 'wecom',
          config: { webhook_url: wecomWebhook.value.trim() }
        })
      }
      if (channels.length > 0) {
        await axios.post('/api/v1/install/notify', { channels }, {
          headers: { 'X-Install-Token': installToken.value }
        })
      }
      await axios.post('/api/v1/install/complete', {}, {
        headers: { 'X-Install-Token': installToken.value }
      })
      currentStep.value = 5
    }
  } catch (err: any) {
    ElMessage.error(err.response?.data?.msg || '操作失败，请核对信息')
  } finally {
    loading.value = false
  }
}

const goToDashboard = () => {
  router.push('/login')
}
</script>

<style scoped>
.install-container {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--grad-bg);
  padding: 24px 16px;
  overflow: hidden;
}

.aurora-blob {
  position: absolute;
  border-radius: 50%;
  filter: blur(80px);
  opacity: 0.45;
  pointer-events: none;
  animation: aurora-float 20s infinite alternate ease-in-out;
}
.blob-1 { width: 450px; height: 450px; background: #93C5FD; top: -100px; left: -100px; }
.blob-2 { width: 500px; height: 500px; background: #60A5FA; bottom: -150px; right: -100px; }
.blob-3 { width: 350px; height: 350px; background: #C7D2FE; top: 40%; left: 60%; }

@keyframes aurora-float {
  0% { transform: translate(0, 0) scale(1); }
  100% { transform: translate(30px, -30px) scale(1.05); }
}

.install-glass-card {
  position: relative;
  z-index: 10;
  width: 100%;
  max-width: 760px;
  background: var(--grad-glass);
  backdrop-filter: blur(24px) saturate(160%);
  border: 1px solid var(--border-glass);
  border-radius: var(--r-xl);
  box-shadow: var(--shadow-lg);
  padding: 40px;
}

.install-header { text-align: center; margin-bottom: 32px; }
.logo-box {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 56px; height: 56px;
  background: var(--grad-brand);
  border-radius: var(--r-md);
  color: #fff;
  margin-bottom: 12px;
  box-shadow: var(--shadow-md);
}
.radar-icon { width: 32px; height: 32px; }
.brand-title { font-size: 24px; font-weight: 700; color: var(--text-1); margin: 0 0 6px 0; }
.brand-subtitle { font-size: 14px; color: var(--text-3); margin: 0; }

.steps-wrapper { display: flex; align-items: center; justify-content: space-between; margin-bottom: 36px; }
.step-item { display: flex; align-items: center; position: relative; flex: 1; }
.step-circle {
  width: 32px; height: 32px;
  border-radius: 50%;
  background: #E2E8F0;
  color: var(--text-2);
  display: flex; align-items: center; justify-content: center;
  font-size: 13px; font-weight: 600;
}
.step-item.active .step-circle {
  background: var(--brand-500);
  color: #fff;
  box-shadow: var(--shadow-glow);
}
.step-item.completed .step-circle { background: var(--success); color: #fff; }
.step-title { margin-left: 10px; font-size: 13px; font-weight: 500; color: var(--text-2); }
.step-item.active .step-title { color: var(--brand-600); font-weight: 600; }
.step-line { flex: 1; height: 2px; background: rgba(59, 130, 246, 0.15); margin: 0 12px; }

.mobile-steps-bar { display: none; font-size: 13px; color: var(--text-2); margin-bottom: 24px; }
.step-content-box { min-height: 280px; }
.pane-title { font-size: 16px; font-weight: 600; color: var(--text-1); margin: 0 0 20px 0; }

.env-list { display: flex; flex-direction: column; gap: 12px; }
.env-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px;
  background: rgba(255, 255, 255, 0.6);
  border-radius: var(--r-md);
  border: 1px solid var(--border);
}
.env-label { font-size: 14px; font-weight: 500; color: var(--text-1); }
.env-desc { font-size: 12px; color: var(--text-3); margin-left: 8px; }
.soft-tag { padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 500; }
.soft-tag.pass { background: var(--success-bg); color: var(--success); }
.soft-tag.fail { background: var(--danger-bg); color: var(--danger); }
.soft-tag.warn { background: var(--warning-bg); color: var(--warning); }

.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.col-span-2 { grid-column: span 2; }
.form-group label { display: block; font-size: 13px; font-weight: 500; color: var(--text-2); margin-bottom: 6px; }
.input-theme {
  width: 100%; box-sizing: border-box;
  padding: 10px 14px;
  border-radius: var(--r-sm);
  border: 1px solid var(--border-strong);
  background: rgba(255, 255, 255, 0.85);
  color: var(--text-1);
  outline: none;
}
.input-theme:focus { border-color: var(--brand-500); box-shadow: var(--shadow-glow); }
.checkbox-group { display: flex; align-items: center; justify-content: space-between; margin-top: 8px; }
.checkbox-label { display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer; }

.install-footer {
  display: flex; align-items: center;
  margin-top: 36px; padding-top: 24px;
  border-top: 1px solid var(--border);
}
.flex-spacer { flex: 1; }
.primary-btn {
  background: var(--grad-brand);
  color: #fff;
  border: none;
  padding: 11px 26px;
  border-radius: var(--r-md);
  font-size: 14px; font-weight: 500;
  cursor: pointer;
  box-shadow: var(--shadow-sm);
}
.ghost-btn {
  background: transparent; color: var(--text-2);
  border: 1px solid var(--border-strong);
  padding: 10px 22px; border-radius: var(--r-md);
  font-size: 14px; cursor: pointer;
}
.ghost-btn-sm {
  background: rgba(255, 255, 255, 0.7);
  border: 1px solid var(--border-strong);
  padding: 6px 14px; border-radius: var(--r-sm);
  font-size: 12px; cursor: pointer;
}

.success-badge {
  width: 64px; height: 64px;
  margin: 0 auto 16px;
  background: var(--success);
  color: #fff;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 32px;
  box-shadow: var(--shadow-glow-success);
}
.security-banner {
  margin-top: 20px; padding: 14px;
  background: var(--warning-bg);
  border: 1px solid var(--warning-border);
  color: #92400E;
  border-radius: var(--r-md);
  font-size: 13px; text-align: left;
}

@media (max-width: 768px) {
  .install-glass-card { padding: 24px 16px; }
  .desktop-steps { display: none; }
  .mobile-steps-bar { display: block; }
  .form-grid { grid-template-columns: 1fr; }
  .col-span-2 { grid-column: span 1; }
}
</style>
