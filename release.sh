#!/bin/bash

# Current Version: 1.2.1

## How to get and use?
# git clone "https://github.com/hezhijie0327/AdFilter.git" && bash ./AdFilter/release.sh

## Function
# Get Data
function GetData() {
    filter_adblock=(
        "https://easylist.to/easylist/easylist.txt"
        "https://easylist.to/easylist/easyprivacy.txt"
        "https://filters.adtidy.org/extension/chromium/filters/1.txt"
        "https://filters.adtidy.org/extension/chromium/filters/101.txt"
        "https://filters.adtidy.org/extension/chromium/filters/102.txt"
        "https://filters.adtidy.org/extension/chromium/filters/103.txt"
        "https://filters.adtidy.org/extension/chromium/filters/104.txt"
        "https://filters.adtidy.org/extension/chromium/filters/105.txt"
        "https://filters.adtidy.org/extension/chromium/filters/106.txt"
        "https://filters.adtidy.org/extension/chromium/filters/107.txt"
        "https://filters.adtidy.org/extension/chromium/filters/108.txt"
        "https://filters.adtidy.org/extension/chromium/filters/109.txt"
        "https://filters.adtidy.org/extension/chromium/filters/11.txt"
        "https://filters.adtidy.org/extension/chromium/filters/110.txt"
        "https://filters.adtidy.org/extension/chromium/filters/111.txt"
        "https://filters.adtidy.org/extension/chromium/filters/112.txt"
        "https://filters.adtidy.org/extension/chromium/filters/113.txt"
        "https://filters.adtidy.org/extension/chromium/filters/114.txt"
        "https://filters.adtidy.org/extension/chromium/filters/115.txt"
        "https://filters.adtidy.org/extension/chromium/filters/116.txt"
        "https://filters.adtidy.org/extension/chromium/filters/117.txt"
        "https://filters.adtidy.org/extension/chromium/filters/118.txt"
        "https://filters.adtidy.org/extension/chromium/filters/119.txt"
        "https://filters.adtidy.org/extension/chromium/filters/12.txt"
        "https://filters.adtidy.org/extension/chromium/filters/120.txt"
        "https://filters.adtidy.org/extension/chromium/filters/121.txt"
        "https://filters.adtidy.org/extension/chromium/filters/122.txt"
        "https://filters.adtidy.org/extension/chromium/filters/123.txt"
        "https://filters.adtidy.org/extension/chromium/filters/13.txt"
        "https://filters.adtidy.org/extension/chromium/filters/14.txt"
        "https://filters.adtidy.org/extension/chromium/filters/15.txt"
        "https://filters.adtidy.org/extension/chromium/filters/16.txt"
        "https://filters.adtidy.org/extension/chromium/filters/17.txt"
        "https://filters.adtidy.org/extension/chromium/filters/2.txt"
        "https://filters.adtidy.org/extension/chromium/filters/200.txt"
        "https://filters.adtidy.org/extension/chromium/filters/201.txt"
        "https://filters.adtidy.org/extension/chromium/filters/203.txt"
        "https://filters.adtidy.org/extension/chromium/filters/204.txt"
        "https://filters.adtidy.org/extension/chromium/filters/205.txt"
        "https://filters.adtidy.org/extension/chromium/filters/206.txt"
        "https://filters.adtidy.org/extension/chromium/filters/207.txt"
        "https://filters.adtidy.org/extension/chromium/filters/208.txt"
        "https://filters.adtidy.org/extension/chromium/filters/209.txt"
        "https://filters.adtidy.org/extension/chromium/filters/210.txt"
        "https://filters.adtidy.org/extension/chromium/filters/211.txt"
        "https://filters.adtidy.org/extension/chromium/filters/212.txt"
        "https://filters.adtidy.org/extension/chromium/filters/213.txt"
        "https://filters.adtidy.org/extension/chromium/filters/214.txt"
        "https://filters.adtidy.org/extension/chromium/filters/215.txt"
        "https://filters.adtidy.org/extension/chromium/filters/216.txt"
        "https://filters.adtidy.org/extension/chromium/filters/217.txt"
        "https://filters.adtidy.org/extension/chromium/filters/218.txt"
        "https://filters.adtidy.org/extension/chromium/filters/219.txt"
        "https://filters.adtidy.org/extension/chromium/filters/220.txt"
        "https://filters.adtidy.org/extension/chromium/filters/221.txt"
        "https://filters.adtidy.org/extension/chromium/filters/222.txt"
        "https://filters.adtidy.org/extension/chromium/filters/223.txt"
        "https://filters.adtidy.org/extension/chromium/filters/224.txt"
        "https://filters.adtidy.org/extension/chromium/filters/225.txt"
        "https://filters.adtidy.org/extension/chromium/filters/226.txt"
        "https://filters.adtidy.org/extension/chromium/filters/227.txt"
        "https://filters.adtidy.org/extension/chromium/filters/228.txt"
        "https://filters.adtidy.org/extension/chromium/filters/229.txt"
        "https://filters.adtidy.org/extension/chromium/filters/230.txt"
        "https://filters.adtidy.org/extension/chromium/filters/231.txt"
        "https://filters.adtidy.org/extension/chromium/filters/232.txt"
        "https://filters.adtidy.org/extension/chromium/filters/233.txt"
        "https://filters.adtidy.org/extension/chromium/filters/234.txt"
        "https://filters.adtidy.org/extension/chromium/filters/235.txt"
        "https://filters.adtidy.org/extension/chromium/filters/236.txt"
        "https://filters.adtidy.org/extension/chromium/filters/237.txt"
        "https://filters.adtidy.org/extension/chromium/filters/238.txt"
        "https://filters.adtidy.org/extension/chromium/filters/239.txt"
        "https://filters.adtidy.org/extension/chromium/filters/240.txt"
        "https://filters.adtidy.org/extension/chromium/filters/241.txt"
        "https://filters.adtidy.org/extension/chromium/filters/242.txt"
        "https://filters.adtidy.org/extension/chromium/filters/243.txt"
        "https://filters.adtidy.org/extension/chromium/filters/244.txt"
        "https://filters.adtidy.org/extension/chromium/filters/245.txt"
        "https://filters.adtidy.org/extension/chromium/filters/246.txt"
        "https://filters.adtidy.org/extension/chromium/filters/247.txt"
        "https://filters.adtidy.org/extension/chromium/filters/249.txt"
        "https://filters.adtidy.org/extension/chromium/filters/3.txt"
        "https://filters.adtidy.org/extension/chromium/filters/4.txt"
        "https://filters.adtidy.org/extension/chromium/filters/5.txt"
        "https://filters.adtidy.org/extension/chromium/filters/6.txt"
        "https://filters.adtidy.org/extension/chromium/filters/7.txt"
        "https://filters.adtidy.org/extension/chromium/filters/8.txt"
        "https://filters.adtidy.org/extension/chromium/filters/9.txt"
        "https://gitee.com/xinggsf/Adblock-Rule/raw/master/mv.txt"
        "https://gitee.com/xinggsf/Adblock-Rule/raw/master/rule.txt"
        "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/combined_disguised_trackers.txt"
        "https://raw.githubusercontent.com/VeleSila/VELE-SILA-List/gh-pages/KaFanList.txt"
        "https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt"
        "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt"
        "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt"
        "https://raw.githubusercontent.com/o0HalfLife0o/list/master/ad-edentw.txt"
        "https://raw.githubusercontent.com/o0HalfLife0o/list/master/ad-mo.txt"
        "https://raw.githubusercontent.com/o0HalfLife0o/list/master/ad-pc.txt"
        "https://raw.githubusercontent.com/o0HalfLife0o/list/master/ad.txt"
        "https://raw.githubusercontent.com/o0HalfLife0o/list/master/ad2.txt"
        "https://raw.githubusercontent.com/o0HalfLife0o/list/master/ad3.txt"
        "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/ABP-FX.txt"
        "https://sub.adtchrome.com/adt-chinalist-easylist.txt"
        "https://www.fanboy.co.nz/enhancedstats.txt"
        "https://www.fanboy.co.nz/fanboy-annoyance.txt"
    )
    filter_domain=(
        "https://gitee.com/damengzhudamengzhu/guanggaoguolv/raw/master/jiekouAD.txt"
        "https://gitlab.com/ZeroDot1/CoinBlockerLists/-/raw/master/list_browser.txt"
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt"
        "https://raw.githubusercontent.com/examplecode/ad-rules-for-xbrowser/master/core-rule-cn.txt"
        "https://raw.githubusercontent.com/hezhijie0327/AdFilter/source/data/data_block.txt"
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt"
    )
    filter_hosts=(
        "https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts"
        "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
        "https://raw.githubusercontent.com/ilpl/ad-hosts/master/hosts"
        "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts"
        "https://raw.githubusercontent.com/neoFelhz/neohosts/gh-pages/full/hosts"
    )
    filter_other=(
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list"
        "https://raw.githubusercontent.com/eHpo1/Rules/master/Surge4/Ruleset/Liby.list"
        "https://raw.githubusercontent.com/lhie1/Rules/master/Surge/Surge%203/Provider/Reject.list"
    )
    filter_white=(
        "https://easylist-downloads.adblockplus.org/exceptionrules.txt"
        "https://filters.adtidy.org/extension/chromium/filters/10.txt"
        "https://gitlab.com/ZeroDot1/CoinBlockerLists/-/raw/master/white_list.txt"
        "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt"
        "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt"
        "https://raw.githubusercontent.com/EnergizedProtection/unblock/master/basic/formats/domains.txt"
        "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/whitelist/master/domains.list"
        "https://raw.githubusercontent.com/VeleSila/yhosts/master/whitelist.txt"
        "https://raw.githubusercontent.com/WildcardTech/Filter-Domain-List/master/whitelist.txt"
        "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt"
        "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt"
        "https://raw.githubusercontent.com/hezhijie0327/AdFilter/source/data/data_allow.txt"
        "https://raw.githubusercontent.com/mkb2091/blockconvert/master/output/whitelist_domains.txt"
        "https://raw.githubusercontent.com/notracking/hosts-blocklists-scripts/master/hostnames.whitelist.txt"
        "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt"
    )
    rm -rf ./Temp && mkdir ./Temp && cd ./Temp
    for filter_adblock_task in "${!filter_adblock[@]}"; do
        curl -s --connect-timeout 15 "${filter_adblock[$filter_adblock_task]}" >> ./filter_adblock.tmp
    done
    for filter_domain_task in "${!filter_domain[@]}"; do
        curl -s --connect-timeout 15 "${filter_domain[$filter_domain_task]}" >> ./filter_domain.tmp
    done
    for filter_hosts_task in "${!filter_hosts[@]}"; do
        curl -s --connect-timeout 15 "${filter_hosts[$filter_hosts_task]}" >> ./filter_hosts.tmp
    done
    for filter_other_task in "${!filter_other[@]}"; do
        curl -s --connect-timeout 15 "${filter_other[$filter_other_task]}" >> ./filter_other.tmp
    done
    for filter_white_task in "${!filter_white[@]}"; do
        curl -s --connect-timeout 15 "${filter_white[$filter_white_task]}" >> ./filter_white.tmp
    done
}
# Analyse Data
function AnalyseData() {
    filter_data=($(cat ./filter_white.tmp | sed "s/[[:space:]]//g;s/0\.0\.0\.0//g;s/127\.0\.0\.1//g;s/\:\:1//g;s/\:\://g" | tr -d "@^|" | tr "A-Z" "a-z" | grep -E "^(([a-z]{1})|([a-z]{1}[a-z]{1})|([a-z]{1}[0-9]{1})|([0-9]{1}[a-z]{1})|([a-z0-9][-\.a-z0-9]{1,61}[a-z0-9]))\.([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$" | sort | uniq > ./filter_allow.tmp && cat ./filter_adblock.tmp ./filter_domain.tmp ./filter_hosts.tmp ./filter_other.tmp | sed "s/[[:space:]]//g;s/0\.0\.0\.0//g;s/127\.0\.0\.1//g;s/\:\:1//g;s/\:\://g;;s/DOMAIN\,//g;s/DOMAIN\-SUFFIX\,//g;s/domain\://g;s/full\://g" | tr -d "^|" | tr "A-Z" "a-z" | grep -E "^(([a-z]{1})|([a-z]{1}[a-z]{1})|([a-z]{1}[0-9]{1})|([0-9]{1}[a-z]{1})|([a-z0-9][-\.a-z0-9]{1,61}[a-z0-9]))\.([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$" | sort | uniq > ./filter_block.tmp && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' ./filter_allow.tmp ./filter_block.tmp | sort | uniq > ./filter_data.tmp && cat ./filter_data.tmp | grep -v "\.\." | awk "{ print $2 }"))
}
# Generate Information
function GenerateInformation() {
    adfilter_checksum=$(date "+%s" | base64)
    adfilter_description="由其他几个过滤器组成的过滤器可以拦截来自网站的广告"
    adfilter_expires="3小时(更新频率)"
    adfilter_homepage="https://github.com/honbolau/AdFilter"
    adfilter_timeupdated=$(date -d @$(echo "${adfilter_checksum}" | base64 -d) "+%Y-%m-%dT%H:%M:%S%:z")
    adfilter_title="Ad Filter"
    adfilter_total=$(sed -n '$=' ./filter_data.tmp)
    adfilter_version=$(curl -s --connect-timeout 15 "https://raw.githubusercontent.com/honbolau/AdFilter/source/release.sh" | grep "Current\ Version" | sed "s/\#\ Current\ Version\:\ //g")-$(date -d @$(echo "${adfilter_checksum}" | base64 -d) "+%Y%m%d")-$((10#$(date -d @$(echo "${adfilter_checksum}" | base64 -d) "+%H") / 3))
    function adfilter_adblock() {
        echo "! Checksum: ${adfilter_checksum}" > ../adfilter_adblock.txt
        echo "! Title: ${adfilter_title} for Adblock (WEB-level)" >> ../adfilter_adblock.txt
        echo "! Description: ${adfilter_description}" >> ../adfilter_adblock.txt
        echo "! Version: ${adfilter_version}" >> ../adfilter_adblock.txt
        echo "! TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_adblock.txt
        echo "! Expires: ${adfilter_expires}" >> ../adfilter_adblock.txt
        echo "! Homepage: ${adfilter_homepage}" >> ../adfilter_adblock.txt
        echo "! Total: ${adfilter_total}" >> ../adfilter_adblock.txt
    }
    function adfilter_adguardhome() {
        echo "! Checksum: ${adfilter_checksum}" > ../adfilter_adguardhome.txt
        echo "! Title: ${adfilter_title} for AdGuard Home (DNS-level)" >> ../adfilter_adguardhome.txt
        echo "! Description: ${adfilter_description}" >> ../adfilter_adguardhome.txt
        echo "! Version: ${adfilter_version}" >> ../adfilter_adguardhome.txt
        echo "! TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_adguardhome.txt
        echo "! Expires: ${adfilter_expires}" >> ../adfilter_adguardhome.txt
        echo "! Homepage: ${adfilter_homepage}" >> ../adfilter_adguardhome.txt
        echo "! Total: ${adfilter_total}" >> ../adfilter_adguardhome.txt
    }
    function adfilter_clash() {
        echo "payload:" > ../adfilter_clash.yaml
        echo "# Checksum: ${adfilter_checksum}" >> ../adfilter_clash.yaml
        echo "# Title: ${adfilter_title} for Clash (DNS-level)" >> ../adfilter_clash.yaml
        echo "# Description: ${adfilter_description}" >> ../adfilter_clash.yaml
        echo "# Version: ${adfilter_version}" >> ../adfilter_clash.yaml
        echo "# TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_clash.yaml
        echo "# Expires: ${adfilter_expires}" >> ../adfilter_clash.yaml
        echo "# Homepage: ${adfilter_homepage}" >> ../adfilter_clash.yaml
        echo "# Total: ${adfilter_total}" >> ../adfilter_clash.yaml
    }
    function adfilter_dnsmasq() {
        echo "# Checksum: ${adfilter_checksum}" > ../adfilter_dnsmasq.conf
        echo "# Title: ${adfilter_title} for Dnsmasq (DNS-level)" >> ../adfilter_dnsmasq.conf
        echo "# Description: ${adfilter_description}" >> ../adfilter_dnsmasq.conf
        echo "# Version: ${adfilter_version}" >> ../adfilter_dnsmasq.conf
        echo "# TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_dnsmasq.conf
        echo "# Expires: ${adfilter_expires}" >> ../adfilter_dnsmasq.conf
        echo "# Homepage: ${adfilter_homepage}" >> ../adfilter_dnsmasq.conf
        echo "# Total: ${adfilter_total}" >> ../adfilter_dnsmasq.conf
    }
    function adfilter_domains() {
        echo "# Checksum: ${adfilter_checksum}" > ../adfilter_domains.txt
        echo "# Title: ${adfilter_title} for Pi-hole (DNS-level)" >> ../adfilter_domains.txt
        echo "# Description: ${adfilter_description}" >> ../adfilter_domains.txt
        echo "# Version: ${adfilter_version}" >> ../adfilter_domains.txt
        echo "# TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_domains.txt
        echo "# Expires: ${adfilter_expires}" >> ../adfilter_domains.txt
        echo "# Homepage: ${adfilter_homepage}" >> ../adfilter_domains.txt
        echo "# Total: ${adfilter_total}" >> ../adfilter_domains.txt
    }
    function adfilter_hosts() {
        echo "# Checksum: ${adfilter_checksum}" > ../adfilter_hosts.txt
        echo "# Title: ${adfilter_title} for AdAway (DNS-level)" >> ../adfilter_hosts.txt
        echo "# Description: ${adfilter_description}" >> ../adfilter_hosts.txt
        echo "# Version: ${adfilter_version}" >> ../adfilter_hosts.txt
        echo "# TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_hosts.txt
        echo "# Expires: ${adfilter_expires}" >> ../adfilter_hosts.txt
        echo "# Homepage: ${adfilter_homepage}" >> ../adfilter_hosts.txt
        echo "# Total: ${adfilter_total}" >> ../adfilter_hosts.txt
        echo "# (DO NOT REMOVE)" >> ../adfilter_hosts.txt
        echo "127.0.0.1 localhost" >> ../adfilter_hosts.txt
        echo "255.255.255.255 broadcasthost" >> ../adfilter_hosts.txt
        echo "::1 ip6-localhost ip6-loopback localhost" >> ../adfilter_hosts.txt
        echo "fe00::0 ip6-localnet" >> ../adfilter_hosts.txt
        echo "ff00::0 ip6-mcastprefix" >> ../adfilter_hosts.txt
        echo "ff02::1 ip6-allnodes" >> ../adfilter_hosts.txt
        echo "ff02::2 ip6-allrouters" >> ../adfilter_hosts.txt
        echo "ff02::3 ip6-allhosts" >> ../adfilter_hosts.txt
        echo "# (DO NOT REMOVE)" >> ../adfilter_hosts.txt
    }
    function adfilter_quantumult() {
        echo "# Checksum: ${adfilter_checksum}" > ../adfilter_quantumult.yaml
        echo "# Title: ${adfilter_title} for Quantumult (DNS-level)" >> ../adfilter_quantumult.yaml
        echo "# Description: ${adfilter_description}" >> ../adfilter_quantumult.yaml
        echo "# Version: ${adfilter_version}" >> ../adfilter_quantumult.yaml
        echo "# TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_quantumult.yaml
        echo "# Expires: ${adfilter_expires}" >> ../adfilter_quantumult.yaml
        echo "# Homepage: ${adfilter_homepage}" >> ../adfilter_quantumult.yaml
        echo "# Total: ${adfilter_total}" >> ../adfilter_quantumult.yaml
    }
    function adfilter_smartdns() {
        echo "# Checksum: ${adfilter_checksum}" > ../adfilter_smartdns.conf
        echo "# Title: ${adfilter_title} for SmartDNS (DNS-level)" >> ../adfilter_smartdns.conf
        echo "# Description: ${adfilter_description}" >> ../adfilter_smartdns.conf
        echo "# Version: ${adfilter_version}" >> ../adfilter_smartdns.conf
        echo "# TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_smartdns.conf
        echo "# Expires: ${adfilter_expires}" >> ../adfilter_smartdns.conf
        echo "# Homepage: ${adfilter_homepage}" >> ../adfilter_smartdns.conf
        echo "# Total: ${adfilter_total}" >> ../adfilter_smartdns.conf
    }
    function adfilter_surge() {
        echo "# Checksum: ${adfilter_checksum}" > ../adfilter_surge.yaml
        echo "# Title: ${adfilter_title} for Surge (DNS-level)" >> ../adfilter_surge.yaml
        echo "# Description: ${adfilter_description}" >> ../adfilter_surge.yaml
        echo "# Version: ${adfilter_version}" >> ../adfilter_surge.yaml
        echo "# TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_surge.yaml
        echo "# Expires: ${adfilter_expires}" >> ../adfilter_surge.yaml
        echo "# Homepage: ${adfilter_homepage}" >> ../adfilter_surge.yaml
        echo "# Total: ${adfilter_total}" >> ../adfilter_surge.yaml
    }
    function adfilter_unbound() {
        echo "# Checksum: ${adfilter_checksum}" > ../adfilter_unbound.conf
        echo "# Title: ${adfilter_title} for Unbound (DNS-level)" >> ../adfilter_unbound.conf
        echo "# Description: ${adfilter_description}" >> ../adfilter_unbound.conf
        echo "# Version: ${adfilter_version}" >> ../adfilter_unbound.conf
        echo "# TimeUpdated: ${adfilter_timeupdated}" >> ../adfilter_unbound.conf
        echo "# Expires: ${adfilter_expires}" >> ../adfilter_unbound.conf
        echo "# Homepage: ${adfilter_homepage}" >> ../adfilter_unbound.conf
        echo "# Total: ${adfilter_total}" >> ../adfilter_unbound.conf
    }
    adfilter_adblock
    adfilter_adguardhome
    adfilter_clash
    adfilter_dnsmasq
    adfilter_domains
    adfilter_hosts
    adfilter_quantumult
    adfilter_smartdns
    adfilter_surge
    adfilter_unbound
}
# Output Data
function OutputData() {
    function FormatedOutputData() {
        for filter_data_task in "${!filter_data[@]}"; do
            echo "||${filter_data[$filter_data_task]}^" >> ../adfilter_adblock.txt
            echo "|${filter_data[$filter_data_task]}^" >> ../adfilter_adguardhome.txt
            echo "  - DOMAIN,${filter_data[$filter_data_task]}" >> ../adfilter_clash.yaml
            echo "address=/${filter_data[$filter_data_task]}/" >> ../adfilter_dnsmasq.conf
            echo "${filter_data[$filter_data_task]}" >> ../adfilter_domains.txt
            echo "0.0.0.0 ${filter_data[$filter_data_task]}" >> ../adfilter_hosts.txt
            echo "DOMAIN,${filter_data[$filter_data_task]},REJECT" >> ../adfilter_quantumult.yaml
            echo ":: ${filter_data[$filter_data_task]}" >> ../adfilter_hosts.txt
            echo "address /${filter_data[$filter_data_task]}/#" >> ../adfilter_smartdns.conf
            echo "DOMAIN,${filter_data[$filter_data_task]}" >> ../adfilter_surge.yaml
            echo "local-zone: \"${filter_data[$filter_data_task]}\" always_nxdomain" >> ../adfilter_unbound.conf
        done
    }
    if [ ! -f "../adfilter_domains.txt" ]; then
        GenerateInformation && FormatedOutputData
        cd .. && rm -rf ./Temp
        exit 0
    else
        cat ../adfilter_domains.txt | head -n $(sed -n '$=' ../adfilter_domains.txt) | tail -n +9 > ./filter_data.old
        if [ "$(diff ./filter_data.tmp ./filter_data.old)" == "" ]; then
            cd .. && rm -rf ./Temp
            exit 0
        else
            GenerateInformation && FormatedOutputData
            cd .. && rm -rf ./Temp
            exit 0
        fi
    fi
}

## Process
# Call GetData
GetData
# Call AnalyseData
AnalyseData
# Call OutputData
OutputData
