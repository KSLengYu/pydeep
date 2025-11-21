# 科幻留言板

一个基于 Flask + Supabase + Vercel 的科幻风格留言板系统。

## 功能特性

### 🚀 用户系统
- 邮箱注册和验证（支持6个邮箱轮询发送）
- 密码登录
- QQ号绑定（显示QQ头像和昵称）
- 个人资料管理
- 密码修改

### 💬 留言功能
- 发布留言和回复
- 留言折叠/展开
- IP地理位置显示
- 设备型号检测
- 游客模式（每日5条限制）
- 管理员认证标识

### 🛡️ 管理系统
- 主管理员和普通管理员
- 留言删除
- 用户封禁
- 角色管理

### 🎨 界面特色
- 科幻风格设计
- 星空背景动画
- 响应式布局
- 实时更新日志

## 技术栈

- **后端**: Python Flask
- **数据库**: Supabase (PostgreSQL)
- **部署**: Vercel
- **前端**: HTML + CSS + JavaScript
- **邮件**: SMTP (支持6个邮箱轮询发送)

## 环境变量配置

在 Vercel 中设置以下环境变量：

```bash
SECRET_KEY=你的Flask密钥
SUPABASE_URL=你的Supabase项目URL
SUPABASE_KEY=你的Supabase API密钥

# 5个网易邮箱
SMTP_USERNAME_1=你的第一个163邮箱地址
SMTP_PASSWORD_1=你的第一个163邮箱授权码
SMTP_USERNAME_2=你的第二个163邮箱地址
SMTP_PASSWORD_2=你的第二个163邮箱授权码
SMTP_USERNAME_3=你的第三个163邮箱地址
SMTP_PASSWORD_3=你的第三个163邮箱授权码
SMTP_USERNAME_4=你的第四个163邮箱地址
SMTP_PASSWORD_4=你的第四个163邮箱授权码
SMTP_USERNAME_5=你的第五个163邮箱地址
SMTP_PASSWORD_5=你的第五个163邮箱授权码

# 1个QQ邮箱
SMTP_USERNAME_6=你的QQ邮箱地址
SMTP_PASSWORD_6=你的QQ邮箱授权码