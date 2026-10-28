<template>
  <div class="notify-page view-enter-active">
    <div class="top-bar">
      <div>
        <h3 class="page-title">告警通知渠道管理中心</h3>
        <p class="page-sub">全面支持企业微信、钉钉、飞书、Telegram、SMTP 邮件与通用 Webhook 聚合推送</p>
      </div>
      <div class="flex-spacer"></div>
      <button class="primary-btn" @click="showAddModal = true">+ 新建告警通道</button>
    </div>

    <!-- 渠道卡片栅格展示 -->
    <div class="cards-grid">
      <div v-for="item in channelList" :key="item.id" class="channel-card">
        <div class="card-top">
          <span class="type-icon">{{ getChannelIcon(item.type) }}</span>
          <div class="chan-meta">
            <strong class="chan-name">{{ item.name }}</strong>
            <span class="chan-type-badge">{{ formatChannelType(item.type) }}</span>
          </div>
          <div class="flex-spacer"></div>
          <el-switch v-model="item.status" :active-value="1" :inactive-value="0" @change="toggleChannel(item)" />
        </div>

        <div class="card-body">
          <div class="info-line">
            <span class="lbl">配置目标:</span>
            <span class="val truncate">{{ getChannelSummary(item) }}</span>
          </div>
          <div class="info-line">
            <span class="lbl">免打扰时段:</span>
            <span class="val">{{ item.silence_start && item.silence_end ? `${item.silence_start} ~ ${item.silence_end}` : '全天推送' }}</span>
          </div>
        </div>

        <div class="card-actions">
          <button class="ghost-btn-sm" :disabled="testingId === item.id" @click="testChannel(item)">
            {{ testingId === item.id ? '发送中...' : '测试发送' }}
          </button>
          <div class="flex-spacer"></div>
          <button class="text-btn danger" @click="deleteChannel(item)">删除</button>
        </div>
      </div>
    </div>

    <!-- 新增全功能渠道弹窗 -->
    <el-dialog v-model="showAddModal" title="新建告警通知通道" width="540px">
      <div class="dialog-form">
        <div class="form-item">
          <label>渠道名称</label>
          <input v-model="form.name" placeholder="如: 应急响应安全群" class="input-custom" />
        </div>
        <div class="form-item">
          <label>渠道类型</label>
          <select v-model="form.type" class="select-theme full-w">
            <option value="wecom">企业微信群机器人 (WeCom)</option>
            <option value="dingtalk">钉钉群机器人 (DingTalk)</option>
            <option value="feishu">飞书群机器人 (Feishu)</option>
            <option value="telegram">Telegram 机器人 (Telegram Bot)</option>
            <option value="email">SMTP 邮件推送 (Email)</option>
            <option value="webhook">通用自定义 Webhook (JSON)</option>
          </select>
        </div>

        <!-- 1. 企业微信 -->
        <div v-if="form.type === 'wecom'" class="form-item">
          <label>企业微信 Webhook 地址</label>
          <input v-model="form.config.webhook_url" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." class="input-custom" />
        </div>

        <!-- 2. 钉钉 -->
        <div v-if="form.type === 'dingtalk'">
          <div class="form-item">
            <label>钉钉机器人 Webhook 地址</label>
            <input v-model="form.config.webhook_url" placeholder="https://oapi.dingtalk.com/robot/send?access_token=..." class="input-custom" />
          </div>
          <div class="form-item">
            <label>加签密钥 Secret (可选)</label>
            <input v-model="form.config.secret" placeholder="SEC••••••••" class="input-custom" />
          </div>
        </div>

        <!-- 3. 飞书 -->
        <div v-if="form.type === 'feishu'">
          <div class="form-item">
            <label>飞书机器人 Webhook 地址</label>
            <input v-model="form.config.webhook_url" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." class="input-custom" />
          </div>
          <div class="form-item">
            <label>签名校验 Secret (可选)</label>
            <input v-model="form.config.secret" placeholder="可选密钥" class="input-custom" />
          </div>
        </div>

        <!-- 4. Telegram -->
        <div v-if="form.type === 'telegram'">
          <div class="form-item">
            <label>Telegram Bot Token</label>
            <input v-model="form.config.bot_token" placeholder="123456789:AAH••••••••••••••••••••••••" class="input-custom" />
          </div>
          <div class="form-item">
            <label>Chat ID (群组或个人ID)</label>
            <input v-model="form.config.chat_id" placeholder="-100123456789 或 @my_channel" class="input-custom" />
          </div>
        </div>

        <!-- 5. SMTP 邮件 -->
        <div v-if="form.type === 'email'" class="email-config-box">
          <div class="form-row">
            <div class="form-item flex-2">
              <label>SMTP 服务器</label>
              <input v-model="form.config.smtp_host" placeholder="smtp.exmail.qq.com" class="input-custom" />
            </div>
            <div class="form-item flex-1">
              <label>端口</label>
              <input v-model.number="form.config.smtp_port" type="number" placeholder="465" class="input-custom" />
            </div>
          </div>
          <div class="form-row">
            <div class="form-item flex-1">
              <label>账号</label>
              <input v-model="form.config.smtp_user" placeholder="alert@company.com" class="input-custom" />
            </div>
            <div class="form-item flex-1">
              <label>授权码 / 密码</label>
              <input v-model="form.config.smtp_pass" type="password" placeholder="••••••••" class="input-custom" />
            </div>
          </div>
          <div class="form-item">
            <label>收信人邮箱</label>
            <input v-model="form.config.to_email" placeholder="sec_admin@company.com" class="input-custom" />
          </div>
        </div>

        <!-- 6. 通用 Webhook -->
        <div v-if="form.type === 'webhook'" class="form-item">
          <label>接收端点 URL</label>
          <input v-model="form.config.webhook_url" placeholder="https://api.yourdomain.com/alerts/webhook" class="input-custom" />
        </div>

        <div class="dialog-footer">
          <button class="ghost-btn" @click="showAddModal = false">取消</button>
          <button class="primary-btn" @click="saveChannel">保存通道</button>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'

const channelList = ref<any[]>([])
const showAddModal = ref(false)
const testingId = ref<number | null>(null)

const form = ref<any>({
  name: '',
  type: 'wecom',
  config: {
    webhook_url: '',
    secret: '',
    bot_token: '',
    chat_id: '',
    smtp_host: 'smtp.exmail.qq.com',
    smtp_port: 465,
    smtp_user: '',
    smtp_pass: '',
    to_email: ''
  }
})

const getChannelIcon = (type: string) => {
  const map: Record<string, string> = {
    wecom: '💬',
    dingtalk: '📌',
    feishu: '🕊️',
    telegram: '✈️',
    email: '📧',
    webhook: '🌐'
  }
  return map[type] || '🔔'
}

const formatChannelType = (type: string) => {
  const map: Record<string, string> = {
    wecom: '企业微信群机器人',
    dingtalk: '钉钉群机器人',
    feishu: '飞书群机器人',
    telegram: 'Telegram 机器人',
    email: 'SMTP 邮件推送',
    webhook: '通用 Webhook'
  }
  return map[type] || type.toUpperCase()
}

const getChannelSummary = (chan: any) => {
  const cfg = chan.config_parsed || {}
  if (chan.type === 'email') {
    return `发件: ${cfg.smtp_user || '-'} (接收: ${cfg.to_email || cfg.smtp_user || '-'})`
  }
  if (chan.type === 'telegram') {
    return `Bot Token: ${cfg.bot_token || '-'} (Chat: ${cfg.chat_id || '-'})`
  }
  return cfg.webhook_url || chan.config || '-'
}

const fetchChannels = async () => {
  try {
    const { data } = await axios.get('/api/v1/notify-channels')
    channelList.value = data.data || []
  } catch (e) {
    ElMessage.error('无法获取渠道列表')
  }
}

const testChannel = async (item: any) => {
  testingId.value = item.id
  try {
    const { data } = await axios.post(`/api/v1/notify-channels/${item.id}/test`)
    ElMessage.success(data.msg || '测试告警消息已成功发出')
  } catch (err: any) {
    ElMessage.error(err.response?.data?.msg || '发送测试失败')
  } finally {
    testingId.value = null
  }
}

const saveChannel = async () => {
  if (!form.value.name.trim()) {
    ElMessage.warning('请填写渠道名称')
    return
  }
  try {
    await axios.post('/api/v1/notify-channels', form.value)
    ElMessage.success('通知渠道已就绪')
    showAddModal.value = false
    fetchChannels()
  } catch (e: any) {
    ElMessage.error('保存失败')
  }
}

const toggleChannel = async (item: any) => {
  try {
    await axios.post('/api/v1/notify-channels', item)
    ElMessage.success('状态已同步')
  } catch (e) {}
}

const deleteChannel = (item: any) => {
  ElMessageBox.confirm(`确认删除 [${item.name}] 吗？`, '警告', { type: 'warning' }).then(async () => {
    await axios.delete(`/api/v1/notify-channels/${item.id}`)
    ElMessage.success('已删除')
    fetchChannels()
  })
}

onMounted(() => {
  fetchChannels()
})
</script>

<style scoped>
.notify-page { display: flex; flex-direction: column; gap: 20px; }
.top-bar { display: flex; align-items: center; }
.page-title { font-size: 18px; font-weight: 700; color: var(--text-1); margin: 0 0 4px 0; }
.page-sub { font-size: 13px; color: var(--text-3); margin: 0; }

.cards-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px;
}
.channel-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--r-lg); padding: 18px; box-shadow: var(--shadow-sm);
  display: flex; flex-direction: column; gap: 14px;
}
.card-top { display: flex; align-items: center; gap: 10px; }
.type-icon { font-size: 24px; }
.chan-name { font-size: 14px; color: var(--text-1); }
.chan-type-badge {
  font-size: 11px; padding: 2px 6px; background: var(--brand-50);
  color: var(--brand-600); border-radius: 4px; margin-left: 6px;
}

.card-body {
  display: flex; flex-direction: column; gap: 6px; font-size: 13px;
  background: var(--bg); padding: 10px 12px; border-radius: var(--r-md);
}
.info-line { display: flex; gap: 8px; }
.info-line .lbl { color: var(--text-3); }
.info-line .val { color: var(--text-2); }
.truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 220px; }

.card-actions { display: flex; align-items: center; border-top: 1px solid var(--border); padding-top: 12px; }
.text-btn { background: none; border: none; font-size: 12px; cursor: pointer; }
.text-btn.danger { color: var(--danger); }

.dialog-form { display: flex; flex-direction: column; gap: 14px; }
.form-row { display: flex; gap: 12px; }
.flex-1 { flex: 1; }
.flex-2 { flex: 2; }
.input-custom {
  width: 100%; box-sizing: border-box; padding: 9px 12px;
  border-radius: var(--r-sm); border: 1px solid var(--border-strong); outline: none;
}
.select-theme {
  padding: 9px 12px; border-radius: var(--r-sm); border: 1px solid var(--border-strong); outline: none;
}
.dialog-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 14px; }
.flex-spacer { flex: 1; }
.primary-btn {
  background: var(--grad-brand); color: #fff; border: none;
  padding: 9px 18px; border-radius: var(--r-md); font-size: 13px; font-weight: 500; cursor: pointer;
}
.ghost-btn {
  background: transparent; color: var(--text-2); border: 1px solid var(--border-strong);
  padding: 8px 16px; border-radius: var(--r-md); font-size: 13px; cursor: pointer;
}
.ghost-btn-sm {
  background: #fff; border: 1px solid var(--border-strong); padding: 5px 12px; border-radius: var(--r-sm); font-size: 12px; cursor: pointer;
}
.full-w { width: 100%; }
</style>
