<?php
declare(strict_types=1);
set_time_limit(180);

/**
 * Scanner Shelly - cerca i dispositivi Shelly su una classe C (es. 192.168.1.x)
 * e mostra il nome impostato dall'utente.
 *
 * Gen1  : GET /shelly (identificazione) + GET /settings (nome)
 * Gen2+ : GET /shelly (include già il nome), fallback su /rpc/Sys.GetConfig
 *
 * Aggiornamenti firmware (solo canale stabile):
 * Gen1  : GET /ota (has_update / new_version), con "forza controllo" anche /ota/check
 * Gen2+ : GET /rpc/Shelly.CheckForUpdate (chiave "stable")
 *
 * Requisiti: PHP con estensione curl, server nella stessa rete dei Shelly.
 */

/** Esegue GET in parallelo. $urls = [chiave => url]. Ritorna [chiave => ['code'=>int,'body'=>string]] */
function multiGet(array $urls, int $batch = 64, int $connectMs = 800, int $totalMs = 2000): array
{
    $results = [];
    foreach (array_chunk($urls, $batch, true) as $chunk) {
        $mh = curl_multi_init();
        $handles = [];
        foreach ($chunk as $key => $url) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER    => true,
                CURLOPT_CONNECTTIMEOUT_MS => $connectMs,
                CURLOPT_TIMEOUT_MS        => $totalMs,
                CURLOPT_FOLLOWLOCATION    => false,
                CURLOPT_NOSIGNAL          => true,
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$key] = $ch;
        }
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) {
                curl_multi_select($mh, 0.2);
            }
        } while ($running && $status === CURLM_OK);

        foreach ($handles as $key => $ch) {
            $results[$key] = [
                'code' => (int) curl_getinfo($ch, CURLINFO_HTTP_CODE),
                'body' => (string) curl_multi_getcontent($ch),
            ];
            curl_multi_remove_handle($mh, $ch);
        }
        curl_multi_close($mh);
    }
    return $results;
}

/** Estrae la versione leggibile (es. "20230913-112003/v1.14.0-gcb84623" -> "1.14.0") */
function shortVer(string $v): string
{
    return preg_match('/(\d+\.\d+\.\d+(?:\.\d+)?)/', $v, $m) ? $m[1] : $v;
}

function isPrivatePrefix(string $prefix): bool
{
    if (!preg_match('/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/', $prefix, $m)) {
        return false;
    }
    [$a, $b, $c] = [(int) $m[1], (int) $m[2], (int) $m[3]];
    if ($a > 255 || $b > 255 || $c > 255) {
        return false;
    }
    return $a === 10
        || ($a === 172 && $b >= 16 && $b <= 31)
        || ($a === 192 && $b === 168);
}

// Prefisso di default: i primi 3 ottetti dell'IP del server
$defaultPrefix = '192.168.1';
if (!empty($_SERVER['SERVER_ADDR']) && preg_match('/^(\d+\.\d+\.\d+)\.\d+$/', $_SERVER['SERVER_ADDR'], $m)) {
    $defaultPrefix = $m[1];
}

$prefix  = trim($_GET['prefix'] ?? $defaultPrefix);
$from    = max(1, min(254, (int) ($_GET['from'] ?? 1)));
$to      = max(1, min(254, (int) ($_GET['to'] ?? 254)));
if ($from > $to) {
    [$from, $to] = [$to, $from];
}
$doScan  = isset($_GET['scan']);
$force   = isset($_GET['force']);
$error   = null;
$devices = [];
$elapsed = 0.0;
$updCount = 0;

if ($doScan) {
    if (!function_exists('curl_multi_init')) {
        $error = 'L\'estensione PHP curl non è attiva.';
    } elseif (!isPrivatePrefix($prefix)) {
        $error = 'Inserisci un prefisso di rete privata valido (es. 192.168.1).';
    } else {
        $t0 = microtime(true);

        // Fase 1: identificazione tramite /shelly
        $urls = [];
        for ($i = $from; $i <= $to; $i++) {
            $ip = "$prefix.$i";
            $urls[$ip] = "http://$ip/shelly";
        }
        $phase1 = multiGet($urls);

        $found = [];
        foreach ($phase1 as $ip => $r) {
            if ($r['code'] !== 200 || $r['body'] === '') {
                continue;
            }
            $j = json_decode($r['body'], true);
            if (!is_array($j) || !isset($j['mac'])) {
                continue;
            }
            $isGen2 = isset($j['gen']) && (int) $j['gen'] >= 2;
            if (!$isGen2 && !isset($j['type'])) {
                continue; // non sembra uno Shelly
            }
            $found[$ip] = [
                'ip'    => $ip,
                'gen'   => $isGen2 ? (int) $j['gen'] : 1,
                'model' => $isGen2 ? ($j['model'] ?? ($j['app'] ?? '')) : ($j['type'] ?? ''),
                'app'   => $j['app'] ?? '',
                'mac'   => strtoupper((string) $j['mac']),
                'fw'    => $isGen2 ? ($j['ver'] ?? '') : ($j['fw'] ?? ''),
                'auth'  => $isGen2 ? !empty($j['auth_en']) : !empty($j['auth']),
                'name'  => $isGen2 ? trim((string) ($j['name'] ?? '')) : '',
                'id'    => $j['id'] ?? '',
                'upd'   => null,   // null = sconosciuto, false = aggiornato, true = aggiornamento disponibile
                'newver' => '',
            ];
        }

        // Fase 2: recupero del nome dove manca
        $urls2 = [];
        foreach ($found as $ip => $d) {
            if ($d['gen'] === 1) {
                $urls2[$ip] = "http://$ip/settings";
            } elseif ($d['name'] === '') {
                $urls2[$ip] = "http://$ip/rpc/Sys.GetConfig";
            }
        }
        if ($urls2) {
            $phase2 = multiGet($urls2, 64, 1000, 3000);
            foreach ($phase2 as $ip => $r) {
                if ($r['code'] !== 200) {
                    continue; // 401 = protetto da password
                }
                $j = json_decode($r['body'], true);
                if (!is_array($j)) {
                    continue;
                }
                if ($found[$ip]['gen'] === 1) {
                    $name = trim((string) ($j['name'] ?? ''));
                    if ($name === '') {
                        $name = (string) ($j['device']['hostname'] ?? '');
                    }
                    $found[$ip]['name'] = $name;
                } else {
                    $found[$ip]['name'] = trim((string) ($j['device']['name'] ?? ''));
                }
            }
        }

        // Fase 3: aggiornamenti firmware stabili
        if ($found) {
            if ($force) {
                $chk = [];
                foreach ($found as $ip => $d) {
                    if ($d['gen'] === 1) {
                        $chk[$ip] = "http://$ip/ota/check";
                    }
                }
                if ($chk) {
                    multiGet($chk, 64, 1000, 5000);
                    sleep(2); // tempo al Gen1 per interrogare il cloud
                }
            }
            $urls3 = [];
            foreach ($found as $ip => $d) {
                $urls3[$ip] = $d['gen'] === 1 ? "http://$ip/ota" : "http://$ip/rpc/Shelly.CheckForUpdate";
            }
            foreach (multiGet($urls3, 64, 1000, 6000) as $ip => $r) {
                if ($r['code'] !== 200) {
                    continue; // 401 = protetto da password
                }
                $j = json_decode($r['body'], true);
                if (!is_array($j)) {
                    continue;
                }
                if ($found[$ip]['gen'] === 1) {
                    if (array_key_exists('has_update', $j)) {
                        $found[$ip]['upd']    = (bool) $j['has_update'];
                        $found[$ip]['newver'] = (string) ($j['new_version'] ?? '');
                    }
                } else {
                    $found[$ip]['upd']    = isset($j['stable']);
                    $found[$ip]['newver'] = (string) ($j['stable']['version'] ?? '');
                }
            }
        }

        uksort($found, fn($a, $b) => ip2long($a) <=> ip2long($b));
        $devices = array_values($found);
        $updCount = count(array_filter($devices, fn($d) => $d['upd'] === true));
        $elapsed = microtime(true) - $t0;
    }
}

function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scanner Shelly</title>
<style>
    :root { --bg:#f5f6f8; --card:#fff; --text:#1c1e21; --muted:#6b7280; --accent:#2563eb; --border:#e5e7eb; --warn:#b45309; }
    @media (prefers-color-scheme: dark) {
        :root { --bg:#111317; --card:#1b1e24; --text:#e8eaed; --muted:#9aa0a6; --accent:#60a5fa; --border:#2c3038; --warn:#fbbf24; }
    }
    * { box-sizing: border-box; }
    html, body { height:100%; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:var(--bg); color:var(--text); padding:16px 24px; }
    .wrap { width:100%; max-width:none; margin:0; }
    h1 { font-size: 1.4rem; margin: 0 0 12px; }
    .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; margin-bottom:16px; }
    form { display:flex; flex-wrap:wrap; gap:12px; align-items:end; }
    label { display:flex; flex-direction:column; font-size:.8rem; color:var(--muted); gap:4px; }
    input { padding:8px 10px; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--text); font-size:1rem; }
    input[name=prefix] { width: 150px; }
    input[type=number] { width: 80px; }
    button { padding:9px 18px; border:0; border-radius:8px; background:var(--accent); color:#fff; font-size:1rem; cursor:pointer; }
    .scroll { overflow-x:auto; }
    table { width:100%; border-collapse:collapse; font-size:1rem; }
    th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); white-space:nowrap; }
    th { color:var(--muted); font-weight:600; font-size:.8rem; text-transform:uppercase; }
    .name { font-weight:600; }
    .muted { color:var(--muted); }
    .warn { color:var(--warn); }
    .err { color:#dc2626; }
    a { color:var(--accent); text-decoration:none; }
    .chk { justify-content:end; }
    .chk span { font-size:.85rem; color:var(--text); padding-bottom:8px; }
    .okc { color:#16a34a; }
    .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:.8rem; font-weight:600; }
    .badge.ok  { background:rgba(22,163,74,.15); color:#16a34a; }
    .badge.up  { background:rgba(245,158,11,.2); color:var(--warn); }
    .badge.unk { background:rgba(107,114,128,.15); color:var(--muted); }
    tr.hasupd td { background:rgba(245,158,11,.07); }
</style>
</head>
<body>
<div class="wrap">
    <h1>🔎 Scanner Shelly</h1>

    <div class="card">
        <form method="get">
            <label>Rete (primi 3 ottetti)
                <input type="text" name="prefix" value="<?= e($prefix) ?>" placeholder="192.168.1" required>
            </label>
            <label>Da
                <input type="number" name="from" min="1" max="254" value="<?= $from ?>">
            </label>
            <label>A
                <input type="number" name="to" min="1" max="254" value="<?= $to ?>">
            </label>
            <label class="chk">
                <span><input type="checkbox" name="force" value="1"<?= $force ? ' checked' : '' ?>> Forza controllo aggiornamenti (Gen1, +2 s)</span>
            </label>
            <button type="submit" name="scan" value="1">Scansiona</button>
        </form>
    </div>

    <?php if ($error): ?>
        <div class="card err"><?= e($error) ?></div>
    <?php elseif ($doScan): ?>
        <div class="card">
            <p class="muted" style="margin-top:0">
                Trovati <strong><?= count($devices) ?></strong> dispositivi Shelly
                in <?= e($prefix) ?>.<?= $from ?>–<?= $to ?>
                (<?= number_format($elapsed, 1) ?> s)
                &middot;
                <?php if ($updCount > 0): ?>
                    <strong class="warn">🔼 <?= $updCount ?> con aggiornamento stabile disponibile</strong>
                <?php else: ?>
                    <span class="okc">✅ nessun aggiornamento stabile disponibile</span>
                <?php endif; ?>
            </p>
            <?php if ($devices): ?>
            <div class="scroll">
            <table>
                <thead>
                    <tr><th>IP</th><th>Nome</th><th>Modello</th><th>Gen</th><th>MAC</th><th>Firmware</th><th>Aggiornamento</th><th></th></tr>
                </thead>
                <tbody>
                <?php foreach ($devices as $d): ?>
                    <tr<?= $d['upd'] === true ? ' class="hasupd"' : '' ?>>
                        <td><a href="http://<?= e($d['ip']) ?>/" target="_blank" rel="noopener"><?= e($d['ip']) ?></a></td>
                        <td class="name">
                            <?php if ($d['name'] !== ''): ?>
                                <?= e($d['name']) ?>
                            <?php else: ?>
                                <span class="muted">— <?= $d['auth'] ? '' : '(nome non impostato)' ?></span>
                            <?php endif; ?>
                            <?php if ($d['auth']): ?>
                                <span class="warn" title="Protetto da password">🔒<?= $d['name'] === '' ? ' protetto' : '' ?></span>
                            <?php endif; ?>
                        </td>
                        <td><?= e((string) $d['model']) ?><?= $d['app'] !== '' && $d['gen'] > 1 ? ' <span class="muted">(' . e((string) $d['app']) . ')</span>' : '' ?></td>
                        <td>Gen<?= (int) $d['gen'] ?></td>
                        <td class="muted"><?= e($d['mac']) ?></td>
                        <td class="muted"><?= e(shortVer((string) $d['fw'])) ?></td>
                        <td>
                            <?php if ($d['upd'] === true): ?>
                                <span class="badge up" title="Firmware stabile disponibile">🔼 <?= e(shortVer($d['newver'])) ?></span>
                            <?php elseif ($d['upd'] === false): ?>
                                <span class="badge ok">✅ aggiornato</span>
                            <?php else: ?>
                                <span class="badge unk" title="<?= $d['auth'] ? 'Protetto da password: controllo non possibile' : 'Informazione non disponibile (offline o senza cloud?)' ?>">❔ <?= $d['auth'] ? '🔒' : 'n/d' ?></span>
                            <?php endif; ?>
                        </td>
                        <td><a href="http://<?= e($d['ip']) ?>/" target="_blank" rel="noopener">Apri</a></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <?php else: ?>
                <p>Nessun Shelly trovato. Controlla che il server sia nella stessa rete e che il prefisso sia corretto.</p>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
    </body>
</html>
