import express from 'express'
import { createClient } from '@supabase/supabase-js'

// ── Config ─────────────────────────────────────────────
const PORT   = process.env.PORT || 3000
const SUPA_URL = process.env.SUPABASE_URL
const SUPA_KEY = process.env.SUPABASE_SERVICE_KEY

if (!SUPA_URL || !SUPA_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_KEY')
  process.exit(1)
}

const db  = createClient(SUPA_URL, SUPA_KEY, { auth: { persistSession: false } })
const app = express()
app.use(express.json({ limit: '64kb' }))

// ── Rate limit buckets (in-memory) ─────────────────────
const buckets = new Map()
function rateLimit(key, max, windowSecs) {
  const now = Date.now()
  let b = buckets.get(key)
  if (!b || now > b.reset) b = { count: 0, reset: now + windowSecs * 1000 }
  b.count++
  buckets.set(key, b)
  return b.count <= max
}
setInterval(() => { const n = Date.now(); for (const [k,v] of buckets) if (n > v.reset) buckets.delete(k) }, 60000)

// ── Auth middleware ─────────────────────────────────────
async function auth(req, res, next) {
  const key = req.headers['x-api-key']
  const ts  = req.headers['x-timestamp']
  if (!key || !ts) return res.status(401).json({ error: 'Unauthorized' })
  if (!/^whk_[a-f0-9]{64}$/.test(key)) return res.status(401).json({ error: 'Unauthorized' })
  if (Math.abs(Math.floor(Date.now() / 1000) - parseInt(ts)) > 30) return res.status(401).json({ error: 'Unauthorized' })
  if (!rateLimit(key + req.path, 60, 10)) return res.status(429).json({ error: 'Too Many Requests' })
  const { data: game } = await db.from('games').select('id,name,settings,is_active').eq('api_key', key).single()
  if (!game?.is_active) return res.status(401).json({ error: 'Unauthorized' })
  req.game = game
  next()
}

// ── Health ──────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, service: 'whack' }))

// ── Heartbeat ───────────────────────────────────────────
app.post('/game/heartbeat', auth, async (req, res) => {
  const { jobId, playerCount = 0, players = [] } = req.body
  if (!jobId) return res.status(400).json({ error: 'Missing jobId' })
  const now = new Date().toISOString()
  await db.from('servers').upsert({
    game_id: req.game.id, job_id: jobId,
    player_count: Math.min(playerCount, 100),
    player_list: players.slice(0, 100),
    last_heartbeat: now, is_alive: true
  }, { onConflict: 'game_id,job_id' })
  await db.from('servers').update({ is_alive: false })
    .eq('game_id', req.game.id).neq('job_id', jobId)
    .lt('last_heartbeat', new Date(Date.now() - 120000).toISOString())
  res.json({ ok: true })
})

// ── Join (ban check) ────────────────────────────────────
app.post('/game/join', auth, async (req, res) => {
  const { robloxId, username = null, jobId } = req.body
  if (!robloxId) return res.status(400).json({ error: 'Missing robloxId' })
  const now = new Date().toISOString()

  const { data: ban } = await db.from('bans').select('id,reason,expires_at')
    .eq('game_id', req.game.id).eq('roblox_id', robloxId).eq('is_active', true).maybeSingle()

  if (ban) {
    if (ban.expires_at && new Date(ban.expires_at) < new Date()) {
      await db.from('bans').update({ is_active: false }).eq('id', ban.id)
    } else {
      return res.json({ banned: true, reason: ban.reason })
    }
  }

  await db.from('players').upsert({
    game_id: req.game.id, roblox_id: robloxId,
    username, last_seen: now, session_start: now
  }, { onConflict: 'game_id,roblox_id' })

  // analytics
  const today = now.slice(0, 10)
  const { data: a } = await db.from('analytics').select('*').eq('game_id', req.game.id).eq('date', today).maybeSingle()
  if (!a) await db.from('analytics').insert({ game_id: req.game.id, date: today, total_sessions: 1, unique_players: 1 })
  else await db.from('analytics').update({ total_sessions: a.total_sessions + 1 }).eq('game_id', req.game.id).eq('date', today)

  res.json({ banned: false })
})

// ── Leave ───────────────────────────────────────────────
app.post('/game/leave', auth, async (req, res) => {
  const { robloxId, sessionMins = 0 } = req.body
  if (!robloxId) return res.status(400).json({ error: 'Missing robloxId' })
  const mins = Math.min(Math.max(0, Math.floor(sessionMins)), 360)
  const { data: p } = await db.from('players').select('playtime_mins')
    .eq('game_id', req.game.id).eq('roblox_id', robloxId).maybeSingle()
  if (p) await db.from('players').update({
    playtime_mins: p.playtime_mins + mins,
    last_seen: new Date().toISOString(), session_start: null
  }).eq('game_id', req.game.id).eq('roblox_id', robloxId)
  res.json({ ok: true })
})

// ── Flag (cheat detection) ──────────────────────────────
app.post('/game/flag', auth, async (req, res) => {
  const { robloxId, username = null, cheatType, action, confidence = 100, evidence = {}, jobId } = req.body
  if (!robloxId || !cheatType || !action) return res.status(400).json({ error: 'Missing fields' })

  const { data: p } = await db.from('players').select('is_whitelisted')
    .eq('game_id', req.game.id).eq('roblox_id', robloxId).maybeSingle()
  if (p?.is_whitelisted) return res.json({ ok: true, ignored: true })

  await db.from('flags').insert({
    game_id: req.game.id, roblox_id: robloxId, username,
    cheat_type: cheatType, confidence: Math.min(100, Math.max(0, confidence)),
    evidence, action_taken: action, job_id: jobId
  })

  // auto-ban if threshold hit
  const threshold = req.game.settings?.anticheat?.auto_ban_on_flags
  if (threshold > 0) {
    const { count } = await db.from('flags').select('*', { count: 'exact', head: true })
      .eq('game_id', req.game.id).eq('roblox_id', robloxId).eq('dismissed', false)
    if (count >= threshold) {
      const { data: existing } = await db.from('bans').select('id')
        .eq('game_id', req.game.id).eq('roblox_id', robloxId).eq('is_active', true).maybeSingle()
      if (!existing) await db.from('bans').insert({
        game_id: req.game.id, roblox_id: robloxId, username,
        reason: `Auto-ban: ${count} cheat flags`, banned_by: 'anticheat'
      })
    }
  }

  // Discord webhook (fired from Railway, not PHP)
  const webhook = req.game.settings?.webhook
  if (webhook) {
    fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `🔨 Whack — ${cheatType.toUpperCase()} Detected`,
          color: 0xd4f500,
          fields: [
            { name: 'Player', value: username || robloxId, inline: true },
            { name: 'Cheat', value: cheatType, inline: true },
            { name: 'Action', value: action, inline: true },
            { name: 'Confidence', value: `${confidence}%`, inline: true },
          ],
          timestamp: new Date().toISOString()
        }]
      })
    }).catch(() => {})
  }

  res.json({ ok: true })
})

// ── Commands (game polls this) ──────────────────────────
app.get('/game/commands', auth, async (req, res) => {
  const { jobId } = req.query
  if (!jobId) return res.status(400).json({ error: 'Missing jobId' })
  const { data: cmds } = await db.from('commands').select('id,type,payload')
    .eq('game_id', req.game.id).eq('is_done', false)
    .or(`target_job_id.is.null,target_job_id.eq.${jobId}`)
    .order('created_at', { ascending: true }).limit(20)
  res.json({ commands: cmds || [] })
})

app.post('/game/commands/ack', auth, async (req, res) => {
  const { id } = req.body
  if (!id) return res.status(400).json({ error: 'Missing id' })
  await db.from('commands').update({ is_done: true, executed_at: new Date().toISOString() })
    .eq('id', id).eq('game_id', req.game.id)
  res.json({ ok: true })
})

// ── Start ───────────────────────────────────────────────
app.use((_, res) => res.status(404).json({ error: 'Not Found' }))
app.use((err, req, res, _) => { console.error(err.message); res.status(500).json({ error: 'Internal Server Error' }) })
app.listen(PORT, () => console.log(`[whack] running on port ${PORT}`))
