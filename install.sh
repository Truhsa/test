#!/bin/bash
#Install LAMP
dnf -y update
systemctl stop iptables
systemctl disable iptables
echo "Р РµРїРѕР·РёС‚РѕСЂРёРё РѕР±РЅРѕРІР»РµРЅС‹ СѓСЃРїРµС€РЅРѕ"
echo "РЈСЃС‚Р°РЅРѕРІРєР° РїР°РєРµС‚РѕРІ LAMP"
dnf -y install httpd
systemctl enable httpd && systemctl start httpd
rm /tmp/vh
while read line
do
echo $line > /tmp/vline
echo "#cat /tmp/vline | awk '{print $1}'">> /tmp/vh
echo "NameVirtualHost cat /tmp/vline | awk '{print $2}'":80>> /tmp/vh
echo "<VirtualHost cat /tmp/vline | awk '{print $2}':80>">> /tmp/vh
echo "DocumentRoot /var/www/cat /tmp/vline | awk '{print $1}'" >> /tmp/vh
echo "ServerName cat /tmp/vline| awk '{print $1}'" >> /tmp/vh
echo "</VirtualHost>">> /tmp/vh
echo " ">> /tmp/vh
done < /root/domains.txt
cat /tmp/vh >> /etc/httpd/conf/httpd.conf
cat << 'EOF' >> /etc/httpd/conf/httpd.conf
<Directory />
Options FollowSymLinks
AllowOverride All
Require all granted
</Directory>
EOF
systemctl start httpd
echo "Apache СѓСЃРїРµС€РЅРѕ СѓСЃС‚Р°РЅРѕРІР»РµРЅ"
dnf -y install mariadb-server
systemctl enable mariadb && systemctl start mariadb
echo "MySQL СѓСЃРїРµС€РЅРѕ СѓСЃС‚Р°РЅРѕРІР»РµРЅРЅР°"
dnf -y install php php-mysql php-pear* php-common php-mbstring php-mcrypt php-devel php-xml php-gd php-intl
echo "PHP СѓСЃРїРµС€РЅРѕ СѓСЃС‚Р°РЅРѕРІР»РµРЅ"
echo "LAMP СѓСЃРїРµС€РЅРѕ СѓСЃС‚Р°РЅРѕРІР»РµРЅ"
sleep 1

echo "Установка и конфигурация Postfix"

groupadd -g 2222 vmail
useradd -r -u 2222 -g vmail -d /var/vmail -c "Virtual Mail User" vmail

yum -y remove exim sendmail
yum -y install postfix cyrus-sasl cyrus-sasl-plain

cp /etc/postfix/main.cf{,.orig}

cat <<'EOF' > /etc/postfix/main.cf
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
mail_owner = postfix
unknown_local_recipient_reject_code = 550
alias_maps = hash:/etc/postfix/aliases
alias_database = $alias_maps
inet_interfaces = all
inet_protocols = ipv4
mydestination = $myhostname, localhost.$mydomain, localhost
debug_peer_level = 2
debugger_command =
         PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin
         ddd $daemon_directory/$process_name $process_id & sleep 5
sendmail_path = /usr/sbin/sendmail.postfix
newaliases_path = /usr/bin/newaliases.postfix
mailq_path = /usr/bin/mailq.postfix
setgid_group = postdrop
html_directory = no
manpage_directory = /usr/share/man
sample_directory = /usr/share/doc/postfix-2.10.1/samples
readme_directory = /usr/share/doc/postfix-2.10.1/README_FILES
relay_domains = *
virtual_alias_maps = hash:/etc/postfix/virtual/aliases
virtual_mailbox_domains = hash:/etc/postfix/virtual/domains
virtual_mailbox_maps = hash:/etc/postfix/virtual/mailboxes
virtual_minimum_uid = 2222
virtual_uid_maps = static:2222
virtual_gid_maps = static:2222
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous
smtpd_sasl_tls_security_options = $smtpd_sasl_security_options
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
EOF

mkdir /etc/postfix/virtual

cat <<'EOF' > /etc/postfix/virtual/domains
example.com OK
EOF

cat <<'EOF' > /etc/postfix/virtual/aliases
postmaster@example.com postmaster
EOF

cat <<'EOF' > /etc/postfix/virtual/mailboxes
user1@example.com example.com/user1/
user2@example.com example.com/user2/
EOF

postmap /etc/postfix/virtual/domains
postmap /etc/postfix/virtual/aliases
postmap /etc/postfix/virtual/mailboxes

systemctl enable postfix
systemctl start postfix

echo "Postfix установлен и настроен."

# Remove old files
rm -f /etc/postfix/vmail_domains
rm -f /etc/postfix/vmail_mailbox
rm -f /etc/postfix/vmail_aliases
rm -f /tmp/vline
rm -f /tmp/vm

# Create empty files
touch /etc/postfix/vmail_domains
touch /etc/postfix/vmail_mailbox
touch /etc/postfix/vmail_aliases

# Populate vmail_domains
while read line; do
  echo "$line OK" >> /tmp/vm
done < /root/domains.txt
cat /tmp/vm > /etc/postfix/vmail_domains

# Populate vmail_mailbox
while read line; do
  domain=$(echo $line | awk '{print $1}')
  echo "abuse@$domain $domain/abuse/" >> /tmp/vm
  echo "info@$domain $domain/info/" >> /tmp/vm
  echo "bounce@$domain $domain/bounce/" >> /tmp/vm
done < /root/domains.txt
cat /tmp/vm > /etc/postfix/vmail_mailbox

# Populate vmail_aliases
while read line; do
  domain=$(echo $line | awk '{print $1}')
  echo "abuse@$domain abuse@$domain" >> /tmp/vm
  echo "info@$domain info@$domain" >> /tmp/vm
  echo "bounce@$domain bounce@$domain" >> /tmp/vm
done < /root/domains.txt
cat /tmp/vm > /etc/postfix/vmail_aliases

# Update postfix maps
postmap /etc/postfix/vmail_domains
postmap /etc/postfix/vmail_mailbox
postmap /etc/postfix/vmail_aliases

# Add submission service to master.cf
echo "submission inet n - n - - smtpd" >> /etc/postfix/master.cf

# Restart postfix
service postfix restart
echo "Postfix успешно установлен"
sleep 1

echo "Установка и конфигурация Dovecot"
yum -y install dovecot
cp /etc/dovecot/dovecot.conf{,.orig}
cat <<EOF > /etc/dovecot/dovecot.conf
listen = *
ssl = no
protocols = pop3 imap
disable_plaintext_auth = no
auth_mechanisms = plain login
mail_access_groups = vmail
default_login_user = vmail
first_valid_uid = 2222
first_valid_gid = 2222
mail_location = maildir:/var/vmail/%d/%n
passdb {
    driver = passwd-file
    args = scheme=SHA1 /etc/dovecot/passwd
}
userdb {
    driver = static
    args = uid=2222 gid=2222 home=/var/vmail/%d/%n allow_all_users=yes
}
service auth {
    unix_listener auth-client {
        group = postfix
        mode = 0660
        user = postfix
    }
    user = root
}
service imap-login {
    process_min_avail = 1
    user = vmail
}
EOF

rm /etc/dovecot/passwd
touch /etc/dovecot/passwd

while read line; do
    domain=$(echo "$line" | awk '{print $1}')
    mailpass=$(echo "$line" | awk '{print $2}')
    user=$(echo "$line" | awk '{print $3}')
    doveadm pw -p "$mailpass" -s sha1 | cut -d '}' -f2 > /tmp/vmp
    echo "$user@$domain:$mailpass" >> /etc/dovecot/passwd
done < /root/domains.txt

rm /tmp/vmp
chown root: /etc/dovecot/passwd
chmod 600 /etc/dovecot/passwd

systemctl enable postfix
systemctl enable dovecot
systemctl restart postfix
systemctl restart dovecot

echo "Dovecot успешно установлен и сконфигурирован"
sleep 1

echo "Установка и конфигурирование Roundcube"

# Обновление системы
yum -y update

# Установка необходимых зависимостей
yum -y install php php-mcrypt php-mbstring php-pear php-fpm php-mysqlnd httpd

# Установка Mail_Mime и Net_SMTP
pear install Mail_Mime
pear install Net_SMTP

# Создание базы данных и пользователя для Roundcube
mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS roundcube;
GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'localhost' IDENTIFIED BY 'roundcube';
FLUSH PRIVILEGES;
EOF

# Конфигурирование Apache
echo "Alias /webmail /var/www/html/roundcube" > /etc/httpd/conf.d/90-roundcube.conf
echo "<Directory /var/www/html/roundcube>" >> /etc/httpd/conf.d/90-roundcube.conf
echo "Options -Indexes" >> /etc/httpd/conf.d/90-roundcube.conf
echo "AllowOverride All" >> /etc/httpd/conf.d/90-roundcube.conf
echo "</Directory>" >> /etc/httpd/conf.d/90-roundcube.conf
echo "<Directory /var/www/html/roundcube/config>" >> /etc/httpd/conf.d/90-roundcube.conf
echo "Order Deny,Allow" >> /etc/httpd/conf.d/90-roundcube.conf
echo "Deny from All" >> /etc/httpd/conf.d/90-roundcube.conf
echo "</Directory>" >> /etc/httpd/conf.d/90-roundcube.conf
echo "<Directory /var/www/html/roundcube/temp>" >> /etc/httpd/conf.d/90-roundcube.conf
echo "Order Deny,Allow" >> /etc/httpd/conf.d/90-roundcube.conf
echo "Deny from All" >> /etc/httpd/conf.d/90-roundcube.conf
echo "</Directory>" >> /etc/httpd/conf.d/90-roundcube.conf
echo "<Directory /var/www/html/roundcube/logs>" >> /etc/httpd/conf.d/90-roundcube.conf
echo "Order Deny,Allow" >> /etc/httpd/conf.d/90-roundcube.conf
echo "Deny from All" >> /etc/httpd/conf.d/90-roundcube.conf
echo "</Directory>" >> /etc/httpd/conf.d/90-roundcube.conf

# Загрузка и установка Roundcube
curl -L "http://sourceforge.net/projects/roundcubemail/files/latest/download?source=files" > /tmp/roundcube-latest.tar.gz
tar -zxf /tmp/roundcube-latest.tar.gz -C /var/www/html
rm -f /tmp/roundcube-latest.tar.gz
mv /var/www/html/roundcubemail-* /var/www/html/roundcube
chown root: -R /var/www/html/roundcube/
chown apache: -R /var/www/html/roundcube/temp/
chown apache: -R /var/www/html/roundcube/logs/

# Импорт начальной структуры базы данных
mysql -u roundcube -proundcube roundcube < /var/www/html/roundcube/SQL/mysql.initial.sql

# Копирование файла настроек и настройка базы данных и SMTP-сервера

cp /var/www/html/roundcube/config/config.inc.php.sample /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['db_dsnw'\] =\).*$|\1 \'mysqli://roundcube:roundcube@localhost/roundcube\';|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['smtp_server'\] =\).*$|\1 \'localhost\';|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['smtp_user'\] =\).*$|\1 \'%u\';|" /var/www/html/roundcube/config/config.inc.php
sed -i "s|^\(\$config\['smtp_pass'\] =\).*$|\1 \'%p\';|" /var/www/html/roundcube/config/config.inc.php
echo "Roundcube СѓСЃРїРµС€РЅРѕ СѓСЃС‚Р°РЅРѕРІР»РµРЅ"
sleep 1

archname=spins.zip

echo "РЎompression of the website archive"
yum -y install unzip >/dev/null 2>/dev/null
wget https://partizanam.ru/cash/spins.zip -O /tmp/$archname >/dev/null 2>/dev/null
rm -f /tmp/vh
rm -f /tmp/vline
while read line
do
echo "$line" > /tmp/vline
echo "cat /tmp/vline | awk '{print $1}'" > /tmp/vh
enddir=cat /tmp/vh
mkdir -p /var/www/$enddir
done < /root/domains.txt
rm -f /tmp/vh
rm -f /tmp/vline
while read line
do
echo "$line" > /tmp/vline
echo "cat /tmp/vline | awk '{print $1}'" > /tmp/vh
enddir=cat /tmp/vh
unzip -q /tmp/$archname -d /var/www/$enddir
done < /root/domains.txt
sleep 5
chown -R apache:apache /var/www
echo "Р Р°РїР°РєРѕРІРєР° С„Р°Р№Р»РѕРІРѕР№ СЃРёСЃС‚РµРјС‹ СЃРµСЂРІРµСЂР° Р·Р°РІРµСЂС€РµРЅР°"
sleep 1

echo "Окончательная проверка конфигурации сервера"
mkdir -p /etc/pmta
rm -f /etc/pmta/virtualhost.txt
touch /etc/pmta/virtualhost.txt
mailpass=$(cat /root/mailpass.txt)
cat << EOF > /etc/pmta/virtualhost.txt
############################################################################
# BEGIN: USERS/VIRTUAL-MTA / VIRTUAL-MTA-POOL / VIRTUAL-PMTA-PATTERN
############################################################################
<smtp-user 67HJfgs>
        password $mailpass
        source {pmta-auth}
</smtp-user>
<source {pmta-auth}>
        smtp-service yes
        always-allow-relaying yes
        require-auth true
        process-x-virtual-mta yes
        default-virtual-mta pmta-pool
        remove-received-headers true
        add-received-header false
        hide-message-source true
process-x-job false
</source>
<smtp-user pmta-pattern>
        password $mailpass
        source {pmta-pattern-auth}
</smtp-user>
<source {pmta-pattern-auth}>
        smtp-service yes
        always-allow-relaying yes
        require-auth true
        process-x-virtual-mta yes
        #default-virtual-mta pmta-pool
        remove-received-headers true
        add-received-header false
        hide-message-source true
        pattern-list pmta-pattern
process-x-job false
</source>
<virtual-mta-pool pmta-pool> 
</virtual-mta-pool>
EOF
echo "Конфигурация успешно проверена"

rm -f /tmp/vh /tmp/vline
while read line; do
  echo $line > /tmp/vline
  echo "virtual-mta `awk '{print $1}' /tmp/vline`-vmta" >> /tmp/vh
done < /root/domains.txt
cat /tmp/vh >> /etc/pmta/virtualhost.txt
echo -e "</virtual-mta-pool>\n<pattern-list pmta-pattern>" >> /etc/pmta/virtualhost.txt
while read line; do
  echo $line > /tmp/vline
  echo "mail-from /@`awk '{print $1}' /tmp/vline`/ virtual-mta=`awk '{print $1}' /tmp/vline`-vmta" >> /tmp/vh
done < /root/domains.txt
cat /tmp/vh >> /etc/pmta/virtualhost.txt
echo "</pattern-list>" >> /etc/pmta/virtualhost.txt
rm -f /tmp/vh /tmp/vline

# Удаляем временные файлы, если они уже существуют
rm -f /tmp/vh /tmp/vline

# Устанавливаем значение переменной num в 1
num=1

# Читаем каждую строку из файла domains.txt и выполняем следующие действия
while read line
do
    # Записываем текущую строку в файл vline
    echo "$line" > /tmp/vline
    
    # Выводим заголовок для текущего домена
    echo "########################################################################################" >> /tmp/vh
    echo "### START DOMAIN - $num ###################################################################" >> /tmp/vh
    echo "########################################################################################" >> /tmp/vh
    echo " " >> /tmp/vh
    
    # Создаем блок smtp-user для текущего домена
    echo "<smtp-user `cat /tmp/vline | awk '{print $1}'`-vmta>" >> /tmp/vh
    echo " password $mailpass" >> /tmp/vh
    echo " source {`cat /tmp/vline | awk '{print $1}'`-vmta-auth}" >> /tmp/vh
    echo "</smtp-user>" >> /tmp/vh
    echo " " >> /tmp/vh
    
    # Создаем блок source для текущего домена
    echo "<source {`cat /tmp/vline | awk '{print $1}'`-vmta-auth}>" >> /tmp/vh
    echo " smtp-service yes" >> /tmp/vh
    echo " always-allow-relaying yes" >> /tmp/vh
    echo " require-auth true" >> /tmp/vh
    echo " process-x-virtual-mta yes" >> /tmp/vh
    echo " default-virtual-mta `cat /tmp/vline | awk '{print $1}'`-vmta" >> /tmp/vh
    echo " remove-received-headers true" >> /tmp/vh
    echo " add-received-header false" >> /tmp/vh
    echo " hide-message-source true" >> /tmp/vh
    echo " process-x-job false" >> /tmp/vh
    echo "</source>" >> /tmp/vh
    echo " " >> /tmp/vh
    
    # Создаем блок virtual-mta для текущего домена
    echo "<virtual-mta `cat /tmp/vline | awk '{print $1}'`-vmta>" >> /tmp/vh
    echo " " >> /tmp/vh
    echo " auto-cold-virtual-mta `cat /tmp/vline | awk '{print $2}'` `cat /tmp/vline | awk '{print $1}'`" >> /tmp/vh
    echo " domain-key key1,`cat /tmp/vline | awk '{print $1}'`,/etc/dkim.key" >> /tmp/vh
    echo " max-smtp-out 850" >> /tmp/vh
    echo "    <domain *>" >> /tmp/vh
    echo "    </domain>" >> /tmp/vh
    echo " smtp-source-host `cat /tmp/vline | awk '{print $2}'` `cat /tmp/vline | awk '{print $1}'`" >> /tmp/vh
    echo "</virtual-mta>" >> /tmp/vh
    echo " " >> /tmp/vh
    
    ## Увеличиваем значение переменной num на 1
num=$((num+1))
done < domains.txt
echo "Конфигурация успешно создана!"

echo "Перезапуск сервисов"
rm /tmp/vm >/dev/null 2>&1
rm /tmp/vh >/dev/null 2>&1
rm /tmp/vline >/dev/null 2>&1
rm /tmp/vmp >/dev/null 2>&1
rm $archname >/dev/null 2>&1
systemctl restart httpd >/dev/null 2>&1
systemctl restart mysqld >/dev/null 2>&1
systemctl restart postfix >/dev/null 2>&1
systemctl restart dovecot >/dev/null 2>&1

ulimit -H -n 10240

sed -i -e "s/^SELINUX=.*/SELINUX=permissive/" /etc/selinux/config
setenforce 0

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F

service iptables save
systemctl stop firewalld
systemctl disable firewalld

yum -y install perl perl-Archive-Zip

wget http://185.103.109.31/pmta_install_domains4.0/package.tgz 2>/dev/null
tar -zxf package.tgz
cd package

rm /etc/dkim.key >/dev/null 2>/dev/null
cp /root/privat-dkim.txt /etc/dkim.key >/dev/null 2>/dev/null

rpm -i PowerMTA-4.5r1.rpm

systemctl stop pmtahttp
systemctl stop pmta

rm -f /etc/pmta/config
rm -f /usr/sbin/pmta
rm -f /usr/sbin/pmtad

test -d /etc/pmta/ && (cp -r fix/etc/pmta/* /etc/pmta/)
test -d /usr/sbin/ && (cp -r fix/usr/sbin/* /usr/sbin/ && chmod +x /usr/sbin/pmt*)

systemctl enable pmta
systemctl start pmta

systemctl enable pmtahttp
systemctl start pmtahttp

systemctl stop iptables.service
systemctl disable iptables.service

systemctl restart httpd

rm -rf package*
cd ..;rm -rf package*
rm -rf my.sh

sleep 1
echo "Установка успешно завершена!"
