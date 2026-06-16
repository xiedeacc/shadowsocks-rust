# futu_session.ps1 — 累积「富途实际用到的腾讯前缀」最小集(留在路由器方案)。
#
# 用法(我在两步之间把控,你只管登录+试下单):
#   .\futu_session.ps1 start    # 杀富途/清DNS/起连接记录/路由器起抓包
#       —— 然后你:登录富途 → 挂一笔远离现价可撤销的限价单 → 撤单 → 告诉我 done
#   .\futu_session.ps1 finish   # 停抓包 → 判 DNS/API → 映射腾讯前缀 → 并入累积集 → 报告
#   .\futu_session.ps1 show     # 打印当前累积前缀集与缩减比
#
# 原理:下单是 API 驱动(NON-DNS),域名规则抓不到 → 只能 IP 路由。
#   凡是「富途连过 + 属腾讯 + 未被 ss-rust 域名解析覆盖(不在 DNS results 里)」的 IP,
#   都映射到它在 tencent_cidr.txt 里的最具体前缀,并入累积集。跑几次会话即收敛。

param([Parameter(Position=0)][ValidateSet('start','finish','show')]$Action='show')

$ErrorActionPreference = 'Stop'
$Repo      = 'D:\code\shadowsocks\shadowsocks-rust'
$CidrFile  = Join-Path $Repo 'tencent_cidr.txt'
$ConnLog   = Join-Path $Repo 'futu_conns.log'
$LoggerPid = Join-Path $Repo '.futu_logger_pid'
$Accum     = Join-Path $Repo 'futu_proxy_prefixes.txt'   # 累积最小前缀集(成果)
$Observed  = Join-Path $Repo 'futu_observed_ips.txt'      # 每次观测到的 IP 流水
$DnsLocal  = Join-Path $Repo '.futu_dns_session.log'      # 每次 finish 拉回的 DNS 日志
$SshHost   = 'openwrt'

function To-UInt32([string]$ip){ $b=[System.Net.IPAddress]::Parse($ip).GetAddressBytes(); [Array]::Reverse($b); [System.BitConverter]::ToUInt32($b,0) }

function Load-Cidrs {
    $FULL=[uint64]4294967295; $list=New-Object System.Collections.ArrayList
    foreach($line in Get-Content $CidrFile){
        $line=$line.Trim()
        if($line -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$'){
            $net=[uint64](To-UInt32 $Matches[1]); $p=[int]$Matches[2]
            $mask= if($p -eq 0){[uint64]0} else { ($FULL -shl (32-$p)) -band $FULL }
            [void]$list.Add([pscustomobject]@{Cidr=$line;Net=($net -band $mask);Mask=$mask;Plen=$p})
        }
    }
    ,$list
}

function Find-Prefix($ip,$cidrs){
    $v=[uint64](To-UInt32 $ip)
    $m=@($cidrs | Where-Object { ($v -band $_.Mask) -eq $_.Net } | Sort-Object Plen -Descending)
    if($m.Count){ $m[0].Cidr } else { $null }
}

function Do-Start {
    Get-Process | Where-Object { $_.Path -like '*\FTNN\*' } | Stop-Process -Force -ErrorAction SilentlyContinue
    ipconfig /flushdns | Out-Null
    Remove-Item $ConnLog -ErrorAction SilentlyContinue
    $p = Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList '-ExecutionPolicy','Bypass','-File',(Join-Path $Repo 'futu_conn_logger.ps1')
    $p.Id | Out-File $LoggerPid -Encoding ascii
    ssh $SshHost '/tmp/futu_cap.sh start' | Out-Host
    Write-Host ""
    Write-Host ">>> 抓包已启动。现在:启动富途 → 登录 → 挂一笔可撤销限价单 → 撤单 → 回来说 done。" -ForegroundColor Cyan
}

function Do-Finish {
    ssh $SshHost '/tmp/futu_cap.sh stop' | Out-Host
    if(Test-Path $LoggerPid){ $lp=(Get-Content $LoggerPid | Select-Object -First 1).Trim(); Stop-Process -Id $lp -Force -ErrorAction SilentlyContinue }
    scp -q "${SshHost}:/tmp/futu/ssrust_dns.log" $DnsLocal

    if(-not (Test-Path $ConnLog)){ Write-Host "未找到 $ConnLog,本次无连接数据。" -ForegroundColor Yellow; return }

    # 1) 本次富途连过的远端 IP(去重)
    $orderIps = Select-String -Path $ConnLog -Pattern '->\s+(\d+\.\d+\.\d+\.\d+):' |
        ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique
    # 2) ss-rust 域名解析覆盖到的 IP(出现在 DNS results 里 → 已被域名规则代理,无需进 proxy_ip)
    $dnsSeen = @{}
    if(Test-Path $DnsLocal){
        Select-String -Path $DnsLocal -Pattern 'results=\[' |
            ForEach-Object { [regex]::Matches($_.Line,'\d+\.\d+\.\d+\.\d+') } |
            ForEach-Object { $_ } | ForEach-Object { $dnsSeen[$_.Value]=$true }
    }

    $cidrs = Load-Cidrs
    $sessNew = New-Object System.Collections.Generic.HashSet[string]
    $nonTencent = @()
    $rows = @()
    foreach($ip in $orderIps){
        $covered = $dnsSeen.ContainsKey($ip)        # 已被域名规则覆盖
        $pref = Find-Prefix $ip $cidrs
        $cls = if($covered){'DNS-covered'} elseif($pref){'NEED-PROXY(腾讯)'} else {'NEED?(非腾讯)'}
        if((-not $covered) -and $pref){ [void]$sessNew.Add($pref) }
        if((-not $covered) -and (-not $pref)){ $nonTencent += $ip }
        $rows += [pscustomobject]@{IP=$ip; 分类=$cls; 腾讯前缀=($pref ?? '-')}
    }

    # 3) 并入累积集
    $existing = @(); if(Test-Path $Accum){ $existing = Get-Content $Accum | Where-Object { $_ -match '\S' } }
    $before = $existing.Count
    $union = [System.Collections.Generic.HashSet[string]]::new([string[]]$existing)
    $addedThisRun = @()
    foreach($c in $sessNew){ if($union.Add($c)){ $addedThisRun += $c } }
    $union | Sort-Object | Set-Content $Accum -Encoding ascii

    # 观测流水
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $orderIps | ForEach-Object { "$stamp`t$_" } | Add-Content $Observed -Encoding ascii

    # 4) 报告
    $totalCidrLines = (Get-Content $CidrFile | Where-Object { $_ -match '/\d+$' }).Count
    Write-Host ""
    Write-Host "================== 本次会话分类 ==================" -ForegroundColor Green
    $rows | Format-Table -Auto | Out-String | Write-Host
    Write-Host "本次新增前缀(并入累积集): $($addedThisRun.Count)" -ForegroundColor Cyan
    if($addedThisRun.Count){ $addedThisRun | Sort-Object | ForEach-Object { Write-Host "    + $_" } }
    if($nonTencent.Count){ Write-Host "非腾讯且未覆盖的直连 IP(需单独看): $($nonTencent -join ', ')" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "累积前缀集: $before → $($union.Count) 条   (全表 $totalCidrLines 条,缩减约 $([math]::Round($union.Count*100.0/$totalCidrLines,2))%)" -ForegroundColor Green
    if($addedThisRun.Count -eq 0){ Write-Host ">>> 本次 0 新增 → 趋于收敛。再跑 1~2 次确认无新增即可定稿。" -ForegroundColor Green }
    else { Write-Host ">>> 本次有新增 → 建议再来一次会话继续收敛。" -ForegroundColor Yellow }
    Write-Host "成果文件: $Accum"
}

function Do-Show {
    if(Test-Path $Accum){
        $p = Get-Content $Accum | Where-Object { $_ -match '\S' }
        $totalCidrLines = (Get-Content $CidrFile | Where-Object { $_ -match '/\d+$' }).Count
        Write-Host "当前累积前缀集($($p.Count) 条,全表 $totalCidrLines 条):" -ForegroundColor Green
        $p | ForEach-Object { Write-Host "    $_" }
    } else { Write-Host "尚无累积集($Accum 不存在),先跑 finish。" -ForegroundColor Yellow }
}

switch($Action){ 'start'{Do-Start} 'finish'{Do-Finish} 'show'{Do-Show} }
