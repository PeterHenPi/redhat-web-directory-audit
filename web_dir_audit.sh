#!/usr/bin/env bash
set -u

# Red Hat Web directory compliance audit
# Checks:
# 1. Web root discovery for Nginx, Apache, Tomcat, Jetty, WebLogic and Uvicorn
# 2. Directory permission baseline
# 3. World-writable files/directories
# 4. Sensitive/high-risk files
# 5. Recent file changes
# 6. SELinux status and context
# 7. Web service process root-user check

SCAN_DAYS=7
MAX_ITEMS=200
EXTRA_PATHS=()

usage() {
  cat <<'EOF'
Usage:
  web_dir_audit.sh [--days N] [--max-items N] [--path PATH ...]

Examples:
  sudo ./web_dir_audit.sh
  sudo ./web_dir_audit.sh --days 30 --path /data/www

Output:
  JSON report to stdout.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --days)
      SCAN_DAYS="${2:-7}"
      shift 2
      ;;
    --max-items)
      MAX_ITEMS="${2:-200}"
      shift 2
      ;;
    --path)
      EXTRA_PATHS+=("${2:-}")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$SCAN_DAYS" in
  ''|*[!0-9]*)
    echo "--days must be a positive integer" >&2
    exit 2
    ;;
esac

case "$MAX_ITEMS" in
  ''|*[!0-9]*)
    echo "--max-items must be a positive integer" >&2
    exit 2
    ;;
esac

TMP_DIR="$(mktemp -d /tmp/web-dir-audit.XXXXXX 2>/dev/null || mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

json_escape() {
  sed \
    -e 's/\\/\\\\/g' \
    -e 's/"/\\"/g' \
    -e 's/	/\\t/g' \
    -e 's/\r/\\r/g'
}

json_value() {
  printf '%s' "$1" | json_escape
}

emit_string_array_file() {
  local file="$1"
  local first=1

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '    "%s"' "$(json_value "$line")"
  done < "$file"
  printf '\n'
}

emit_object_array_file() {
  local file="$1"
  local first=1

  while IFS='|' read -r path type mode user group size mtime detail; do
    [ -n "${path:-}" ] || continue
    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '    {"path":"%s","type":"%s","mode":"%s","user":"%s","group":"%s","size":%s,"mtime":"%s","detail":"%s"}' \
      "$(json_value "$path")" \
      "$(json_value "$type")" \
      "$(json_value "$mode")" \
      "$(json_value "$user")" \
      "$(json_value "$group")" \
      "${size:-0}" \
      "$(json_value "$mtime")" \
      "$(json_value "$detail")"
  done < "$file"
  printf '\n'
}

emit_process_array_file() {
  local file="$1"
  local first=1

  while IFS='|' read -r service pid user is_root command; do
    [ -n "${pid:-}" ] || continue
    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '    {"service":"%s","pid":%s,"user":"%s","is_root":%s,"command":"%s"}' \
      "$(json_value "$service")" \
      "${pid:-0}" \
      "$(json_value "$user")" \
      "${is_root:-false}" \
      "$(json_value "$command")"
  done < "$file"
  printf '\n'
}

stat_record() {
  local path="$1"
  local detail="${2:-}"
  local stat_out type mode user group size mtime

  stat_out="$(stat -c '%F|%a|%U|%G|%s|%y' "$path" 2>/dev/null || true)"
  [ -n "$stat_out" ] || return 0

  type="$(printf '%s' "$stat_out" | awk -F'|' '{print $1}')"
  mode="$(printf '%s' "$stat_out" | awk -F'|' '{print $2}')"
  user="$(printf '%s' "$stat_out" | awk -F'|' '{print $3}')"
  group="$(printf '%s' "$stat_out" | awk -F'|' '{print $4}')"
  size="$(printf '%s' "$stat_out" | awk -F'|' '{print $5}')"
  mtime="$(printf '%s' "$stat_out" | cut -d'|' -f6- | sed 's/\..*$//')"

  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$path" "$type" "$mode" "$user" "$group" "$size" "$mtime" "$detail"
}

HOSTNAME_VALUE="$(hostname 2>/dev/null || uname -n)"
SCAN_TIME="$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')"

APACHE_ROOTS="$TMP_DIR/apache_roots.txt"
NGINX_ROOTS="$TMP_DIR/nginx_roots.txt"
TOMCAT_ROOTS="$TMP_DIR/tomcat_roots.txt"
JETTY_ROOTS="$TMP_DIR/jetty_roots.txt"
WEBLOGIC_ROOTS="$TMP_DIR/weblogic_roots.txt"
UVICORN_ROOTS="$TMP_DIR/uvicorn_roots.txt"
WEB_ROOTS="$TMP_DIR/web_roots.txt"
DIR_BASELINE="$TMP_DIR/dir_baseline.txt"
WORLD_WRITABLE="$TMP_DIR/world_writable.txt"
SENSITIVE_FILES="$TMP_DIR/sensitive_files.txt"
RECENT_CHANGES="$TMP_DIR/recent_changes.txt"
SELINUX_CONTEXTS="$TMP_DIR/selinux_contexts.txt"
WEB_SERVICE_PROCESSES="$TMP_DIR/web_service_processes.txt"
FIND_ERRORS="$TMP_DIR/find_errors.txt"

: > "$APACHE_ROOTS"
: > "$NGINX_ROOTS"
: > "$TOMCAT_ROOTS"
: > "$JETTY_ROOTS"
: > "$WEBLOGIC_ROOTS"
: > "$UVICORN_ROOTS"
: > "$WEB_ROOTS"
: > "$DIR_BASELINE"
: > "$WORLD_WRITABLE"
: > "$SENSITIVE_FILES"
: > "$RECENT_CHANGES"
: > "$SELINUX_CONTEXTS"
: > "$WEB_SERVICE_PROCESSES"
: > "$FIND_ERRORS"

if [ -d /etc/httpd ]; then
  grep -RihE '^[[:space:]]*(DocumentRoot|Alias)[[:space:]]+' /etc/httpd 2>/dev/null \
    | awk '
        BEGIN {IGNORECASE=1}
        $1 == "DocumentRoot" {print $2}
        $1 == "Alias" && NF >= 3 {print $3}
      ' \
    | tr -d '";' \
    | sed '/^[[:space:]]*$/d' \
    | sort -u > "$APACHE_ROOTS"
fi

if [ -d /etc/nginx ]; then
  grep -RihE '^[[:space:]]*(root|alias)[[:space:]]+' /etc/nginx 2>/dev/null \
    | awk '{print $2}' \
    | tr -d '";' \
    | sed '/^[[:space:]]*$/d' \
    | sort -u > "$NGINX_ROOTS"
fi

{
  if [ -d /etc/tomcat ]; then
    grep -RihE 'appBase=|docBase=' /etc/tomcat 2>/dev/null || true
  fi
  for d in /etc/tomcat* /opt/tomcat*/conf /usr/local/tomcat*/conf; do
    [ -d "$d" ] && grep -RihE 'appBase=|docBase=' "$d" 2>/dev/null || true
  done
} | sed -nE 's/.*(appBase|docBase)[[:space:]]*=[[:space:]]*"([^"]+)".*/\2/p' \
  | sed '/^[[:space:]]*$/d' \
  | sort -u > "$TOMCAT_ROOTS"

for d in \
  /var/lib/tomcat/webapps \
  /var/lib/tomcat*/webapps \
  /usr/share/tomcat/webapps \
  /usr/share/tomcat*/webapps \
  /opt/tomcat/webapps \
  /opt/tomcat*/webapps \
  /usr/local/tomcat/webapps \
  /usr/local/tomcat*/webapps
do
  [ -d "$d" ] && printf '%s\n' "$d" >> "$TOMCAT_ROOTS"
done
sort -u "$TOMCAT_ROOTS" -o "$TOMCAT_ROOTS"

{
  for d in /etc/jetty /etc/jetty* /opt/jetty*/etc /usr/local/jetty*/etc; do
    [ -d "$d" ] && grep -RihE 'jetty.base|jetty.home|webapps' "$d" 2>/dev/null || true
  done
} | sed -nE 's/.*(jetty.base|jetty.home)[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\2/p' \
  | sed 's#/etc$##' \
  | while IFS= read -r jetty_base; do
      [ -n "$jetty_base" ] && printf '%s/webapps\n' "$jetty_base"
    done \
  | sed '/^[[:space:]]*$/d' \
  | sort -u > "$JETTY_ROOTS"

for d in \
  /var/lib/jetty/webapps \
  /var/lib/jetty*/webapps \
  /opt/jetty/webapps \
  /opt/jetty*/webapps \
  /usr/local/jetty/webapps \
  /usr/local/jetty*/webapps
do
  [ -d "$d" ] && printf '%s\n' "$d" >> "$JETTY_ROOTS"
done
sort -u "$JETTY_ROOTS" -o "$JETTY_ROOTS"

for d in \
  /u01/oracle/user_projects/domains/*/autodeploy \
  /u01/app/oracle/user_projects/domains/*/autodeploy \
  /opt/oracle/user_projects/domains/*/autodeploy \
  /opt/weblogic/user_projects/domains/*/autodeploy \
  /var/opt/weblogic/user_projects/domains/*/autodeploy
do
  [ -d "$d" ] && printf '%s\n' "$d" >> "$WEBLOGIC_ROOTS"
done

for f in \
  /u01/oracle/user_projects/domains/*/config/config.xml \
  /u01/app/oracle/user_projects/domains/*/config/config.xml \
  /opt/oracle/user_projects/domains/*/config/config.xml \
  /opt/weblogic/user_projects/domains/*/config/config.xml \
  /var/opt/weblogic/user_projects/domains/*/config/config.xml
do
  [ -f "$f" ] || continue
  sed -nE 's#.*<source-path>(.*)</source-path>.*#\1#p' "$f" 2>/dev/null \
    | while IFS= read -r source_path; do
        [ -d "$source_path" ] && printf '%s\n' "$source_path"
      done >> "$WEBLOGIC_ROOTS"
done
sort -u "$WEBLOGIC_ROOTS" -o "$WEBLOGIC_ROOTS"

if [ -d /proc ]; then
  ps -eo pid=,args= 2>/dev/null \
    | grep -E '[u]vicorn|[g]unicorn.*uvicorn|[p]ython.*uvicorn' \
    | while read -r pid args; do
        app_dir="$(printf '%s\n' "$args" | sed -nE 's/.*--app-dir[= ]([^ ]+).*/\1/p' | head -n 1)"
        if [ -n "$app_dir" ] && [ -d "$app_dir" ]; then
          printf '%s\n' "$app_dir"
        elif [ -L "/proc/$pid/cwd" ]; then
          readlink "/proc/$pid/cwd" 2>/dev/null || true
        fi
      done > "$UVICORN_ROOTS"
fi
for d in /opt/* /srv/* /var/www/*; do
  [ -d "$d" ] && find "$d" -maxdepth 2 -type f \( -name 'main.py' -o -name 'app.py' -o -name 'asgi.py' \) -print 2>/dev/null \
    | while IFS= read -r pyfile; do
        dirname "$pyfile"
      done >> "$UVICORN_ROOTS"
done
sort -u "$UVICORN_ROOTS" -o "$UVICORN_ROOTS"

ps -eo pid=,user=,comm=,args= 2>/dev/null \
  | awk '
      {
        pid=$1
        user=$2
        comm=$3
        args=$0
        sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*/, "", args)
        line=tolower(comm " " args)
        service=""

        if (line ~ /(^| )nginx(:| |$)/ || line ~ /\/nginx( |$)/) {
          service="nginx"
        } else if (line ~ /(^| )(httpd|apache2)(:| |$)/ || line ~ /\/(httpd|apache2)( |$)/) {
          service="apache"
        } else if (line ~ /(org\.apache\.catalina|catalina\.home|catalina\.base|tomcat|bootstrap\.jar)/) {
          service="tomcat"
        } else if (line ~ /(start\.jar|jetty\.home|jetty\.base|jetty)/) {
          service="jetty"
        } else if (line ~ /(weblogic\.server|startweblogic|weblogic\.name|bea\.home)/) {
          service="weblogic"
        } else if (line ~ /(uvicorn|gunicorn.*uvicorn)/) {
          service="uvicorn"
        }

        if (service != "") {
          gsub(/\|/, " ", args)
          printf "%s|%s|%s|%s|%s\n", service, pid, user, (user == "root" ? "true" : "false"), args
        }
      }
    ' \
  | sort -u > "$WEB_SERVICE_PROCESSES"

{
  cat "$APACHE_ROOTS"
  cat "$NGINX_ROOTS"
  cat "$TOMCAT_ROOTS"
  cat "$JETTY_ROOTS"
  cat "$WEBLOGIC_ROOTS"
  cat "$UVICORN_ROOTS"
  printf '%s\n' /var/www/html /usr/share/nginx/html
  for p in "${EXTRA_PATHS[@]}"; do
    [ -n "$p" ] && printf '%s\n' "$p"
  done
} | sed 's#/$##' | sed '/^[[:space:]]*$/d' | awk '$0 ~ /^\//' | sort -u > "$WEB_ROOTS"

while IFS= read -r root; do
  [ -d "$root" ] || continue

  stat_record "$root" "web_root" >> "$DIR_BASELINE"

  find "$root" -xdev \( -type d -o -type f \) -perm -0002 -print 2>>"$FIND_ERRORS" \
    | head -n "$MAX_ITEMS" \
    | while IFS= read -r item; do
        stat_record "$item" "world_writable"
      done >> "$WORLD_WRITABLE"

  find "$root" -xdev \( \
      \( -type d \( -name '.git' -o -name '.svn' -o -name '.hg' \) \) -o \
      \( -type f \( \
        -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.save' -o \
        -name '*.zip' -o -name '*.tar' -o -name '*.gz' -o -name '*.tgz' -o -name '*.rar' -o -name '*.7z' -o \
        -name '*.sql' -o -name '*.db' -o -name '*.sqlite' -o \
        -name '.env' -o -name 'config.php' -o -name 'application.yml' -o -name 'application.yaml' -o \
        -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.jks' -o \
        -name '*.log' -o -name 'phpinfo.php' -o -name 'test.php' -o -name '*~' -o -name '*.swp' \
      \) \) \
    \) -print 2>>"$FIND_ERRORS" \
    | head -n "$MAX_ITEMS" \
    | while IFS= read -r item; do
        stat_record "$item" "sensitive_file"
      done >> "$SENSITIVE_FILES"

  find "$root" -xdev \( -type f -o -type d \) \( -mtime "-$SCAN_DAYS" -o -ctime "-$SCAN_DAYS" \) -print 2>>"$FIND_ERRORS" \
    | head -n "$MAX_ITEMS" \
    | while IFS= read -r item; do
        stat_record "$item" "changed_within_${SCAN_DAYS}_days"
      done >> "$RECENT_CHANGES"

  if command -v ls >/dev/null 2>&1; then
    ls -Zd "$root" 2>/dev/null >> "$SELINUX_CONTEXTS" || true
  fi
done < "$WEB_ROOTS"

SELINUX_STATUS="unknown"
if command -v getenforce >/dev/null 2>&1; then
  SELINUX_STATUS="$(getenforce 2>/dev/null || echo unknown)"
elif [ -f /sys/fs/selinux/enforce ]; then
  if [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "1" ]; then
    SELINUX_STATUS="Enforcing"
  else
    SELINUX_STATUS="Permissive"
  fi
fi

CONFIG_CHANGES="$TMP_DIR/config_changes.txt"
: > "$CONFIG_CHANGES"
for config_dir in \
  /etc/httpd \
  /etc/nginx \
  /etc/tomcat \
  /etc/tomcat* \
  /etc/jetty \
  /etc/jetty* \
  /opt/tomcat*/conf \
  /usr/local/tomcat*/conf \
  /opt/jetty*/etc \
  /usr/local/jetty*/etc \
  /u01/oracle/user_projects/domains/*/config \
  /u01/app/oracle/user_projects/domains/*/config \
  /opt/oracle/user_projects/domains/*/config \
  /opt/weblogic/user_projects/domains/*/config \
  /var/opt/weblogic/user_projects/domains/*/config
do
  [ -d "$config_dir" ] || continue
  find "$config_dir" -xdev -type f \( -mtime "-$SCAN_DAYS" -o -ctime "-$SCAN_DAYS" \) -print 2>>"$FIND_ERRORS" \
    | head -n "$MAX_ITEMS" \
    | while IFS= read -r item; do
        stat_record "$item" "web_config_changed_within_${SCAN_DAYS}_days"
      done >> "$CONFIG_CHANGES"
done

cat <<EOF
{
  "hostname": "$(json_value "$HOSTNAME_VALUE")",
  "scan_time": "$(json_value "$SCAN_TIME")",
  "scan_days": $SCAN_DAYS,
  "max_items_per_check": $MAX_ITEMS,
  "checks": {
    "web_root_discovery": {
      "apache_document_roots_and_aliases": [
EOF
emit_string_array_file "$APACHE_ROOTS"
cat <<EOF
      ],
      "nginx_roots_and_aliases": [
EOF
emit_string_array_file "$NGINX_ROOTS"
cat <<EOF
      ],
      "tomcat_app_bases_and_doc_bases": [
EOF
emit_string_array_file "$TOMCAT_ROOTS"
cat <<EOF
      ],
      "jetty_webapp_roots": [
EOF
emit_string_array_file "$JETTY_ROOTS"
cat <<EOF
      ],
      "weblogic_deploy_roots": [
EOF
emit_string_array_file "$WEBLOGIC_ROOTS"
cat <<EOF
      ],
      "uvicorn_app_roots": [
EOF
emit_string_array_file "$UVICORN_ROOTS"
cat <<EOF
      ],
      "effective_web_roots": [
EOF
emit_string_array_file "$WEB_ROOTS"
cat <<EOF
      ]
    },
    "directory_permission_baseline": [
EOF
emit_object_array_file "$DIR_BASELINE"
cat <<EOF
    ],
    "world_writable_items": [
EOF
emit_object_array_file "$WORLD_WRITABLE"
cat <<EOF
    ],
    "sensitive_files": [
EOF
emit_object_array_file "$SENSITIVE_FILES"
cat <<EOF
    ],
    "recent_changes": {
      "web_directory_changes": [
EOF
emit_object_array_file "$RECENT_CHANGES"
cat <<EOF
      ],
      "web_config_changes": [
EOF
emit_object_array_file "$CONFIG_CHANGES"
cat <<EOF
      ]
    },
    "web_service_processes": [
EOF
emit_process_array_file "$WEB_SERVICE_PROCESSES"
cat <<EOF
    ],
    "selinux": {
      "status": "$(json_value "$SELINUX_STATUS")",
      "contexts": [
EOF
emit_string_array_file "$SELINUX_CONTEXTS"
cat <<EOF
      ]
    }
  },
  "errors": [
EOF
sort -u "$FIND_ERRORS" | head -n "$MAX_ITEMS" > "$TMP_DIR/errors_limited.txt"
emit_string_array_file "$TMP_DIR/errors_limited.txt"
cat <<EOF
  ]
}
EOF
