# redhat-web-directory-audit

Red Hat Web 目录自动检测脚本

`web_dir_audit.sh` 用于检测 Red Hat 服务器 Web 目录的 6 个最小落地项，支持识别：

- Nginx
- Apache HTTP Server
- Tomcat
- Jetty
- WebLogic
- Uvicorn


1. Web 根目录和应用部署目录
2. 目录权限
3. 任意用户可写文件/目录
4. 高风险敏感文件
5. 最近变更文件

## 单机执行

```bash
sudo ./web_dir_audit.sh
```

指定最近变更检测天数：

```bash
sudo ./web_dir_audit.sh --days 30
```

补充业务 Web 目录：

```bash
sudo ./web_dir_audit.sh --path /data/www --path /opt/app/html
```

输出为 JSON，可直接保存：

```bash
sudo ./web_dir_audit.sh > web_dir_audit_$(hostname)_$(date +%F).json
```

## Ansible 调用示例

```yaml
---
- name: Red Hat web directory audit
  hosts: redhat_web
  become: true
  gather_facts: false

  tasks:
    - name: Upload web directory audit script
      copy:
        src: web_dir_audit.sh
        dest: /tmp/web_dir_audit.sh
        mode: '0755'

    - name: Run web directory audit
      command: /tmp/web_dir_audit.sh --days 7 --max-items 200
      register: web_dir_audit
      changed_when: false

    - name: Save audit report on target
      copy:
        content: "{{ web_dir_audit.stdout }}"
        dest: "/tmp/{{ inventory_hostname }}_web_dir_audit.json"
        mode: '0600'

    - name: Fetch audit report to control node
      fetch:
        src: "/tmp/{{ inventory_hostname }}_web_dir_audit.json"
        dest: "./reports/{{ inventory_hostname }}_web_dir_audit.json"
        flat: true
```

## 结果字段说明

- `web_root_discovery`: 从 Nginx、Apache、Tomcat、Jetty、WebLogic、Uvicorn 配置、默认路径和进程信息识别出的 Web 根目录或应用部署目录
- `directory_permission_baseline`: Web 根目录权限、属主、属组、修改时间
- `world_writable_items`: `other` 可写的文件或目录，通常为高风险
- `sensitive_files`: 备份包、数据库文件、密钥、日志、`.env`、测试页面等风险文件
- `recent_changes`: 最近 N 天 Web 目录和 Web 配置文件的变更
- `web_service_processes`: Nginx、Apache、Tomcat、Jetty、WebLogic、Uvicorn 相关进程及启动用户，`is_root: true` 表示进程由 root 用户启动
- `selinux`: SELinux 状态及 Web 根目录安全上下文
- `errors`: 检测过程中的权限不足或访问失败信息