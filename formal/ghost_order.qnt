// AugustUnlock: what the screen shows against what the lock really did, when
// a command is replaced, timed out or dropped while August still holds it
// (TRIAL 2026-11-07). august_unlock_command.qnt has one `door`, the shown
// one; this model adds the real door, each held command's direction and
// whether August runs them in order.
//
// screenHonest: the screen never shows a door state the lock is not in.
// honestOrWarned: or, if it does, the "may still move the door" line shows.
// `ghostBefore` is the app before #77 and violates both; `ghostWarned` is the
// app now (CommandMachine's warning, door unknown on expiry) and holds
// honestOrWarned whether or not August keeps order (`ghostWarnedAnyOrder`).
// The model's warning never expires; the app's lasts 60 s, a bridged lock's
// worst case, so a command August holds longer than that is not covered.
//
// max-steps: 14
// verify: search-only  (lists of held commands; not yet sized for Apalache in CI)
module ghost_order {
  // A1 ordering: true = August runs held cloud commands in arrival order.
  const fifo: bool
  // Fix (a): dropping a command that reached the cloud sets a standing warning.
  const warnOnGhost: bool
  // Fix (b): once a command reached the cloud, the next one also goes to the cloud.
  const cloudAfterCloud: bool
  // Fix (c): keepAliveExpired shows `unknown`, as the 30 s timeout does.
  const keepAliveUnknown: bool

  type Door = Locked | Unlocked
  type Shown = SLocked | SUnlocked | SUnknown
  type Tr = Ble | BleWritten | Cloud
  type Held = { dir: bool, cur: bool }   // dir true = unlock; cur = the phone still waits

  type S = {
    real: Door, shown: Shown, busy: bool, dirNow: bool, tr: Tr,
    august: List[Held], warned: bool, cloudSeen: bool
  }
  var st: S

  action init = st' = {
    real: Locked, shown: SUnknown, busy: false, dirNow: true, tr: Ble,
    august: List(), warned: false, cloudSeen: false
  }

  pure def asShown(d: Door): Shown = if (d == Locked) SLocked else SUnlocked
  pure def toDoor(unlock: bool): Door = if (unlock) Unlocked else Locked

  // The command in flight is dropped. A cloud one stays at August.
  pure def drop(s: S): S =
    if (s.busy and s.tr == Cloud)
      s.with("august", s.august.foldl(List(), (acc, h) => acc.append({ dir: h.dir, cur: false })))
       .with("warned", s.warned or warnOnGhost)
    else s

  // `perform(.send)`: cancel the command in flight, start this one.
  pure def send(s0: S, unlock: bool): S = {
    val s = drop(s0)
    val toCloud = cloudAfterCloud and s.cloudSeen
    s.with("busy", true).with("dirNow", unlock)
     .with("tr", if (toCloud) Cloud else Ble)
     .with("august", if (toCloud) s.august.append({ dir: unlock, cur: true }) else s.august)
  }

  // The button: the opposite of a command in flight, else lock if shown unlocked.
  action tap = st' = send(st, if (st.busy) not(st.dirNow) else st.shown != SUnlocked)

  // The write reaches the lock (it lands now, in link order).
  action bleWrites = all { st.busy, st.tr == Ble, st' = st.with("tr", BleWritten).with("real", toDoor(st.dirNow)) }
  action bleReplies = all {
    st.busy, st.tr == BleWritten,
    st' = st.with("busy", false).with("tr", Ble).with("shown", asShown(toDoor(st.dirNow)))
  }
  // Bluetooth failed before the write: the command falls to the cloud.
  action bleFalls = all {
    st.busy, st.tr == Ble,
    st' = st.with("tr", Cloud).with("august", st.august.append({ dir: st.dirNow, cur: true })).with("cloudSeen", true)
  }
  // The 30 s deadline, Change Lock, Sign Out: drop the command; the screen says unknown.
  action timeOut = all { st.busy, st' = drop(st).with("busy", false).with("tr", Ble).with("shown", SUnknown) }
  // `keepAliveExpired`: iOS takes the background time; command dropped, `door` stays.
  action keepAliveExpired = all {
    st.busy,
    st' = drop(st).with("busy", false).with("tr", Ble)
            .with("shown", if (keepAliveUnknown) SUnknown else st.shown)
  }
  // August runs one held command. If the phone still waits, it gets the reply.
  action augustRuns = all {
    st.august.length() > 0,
    nondet i = oneOf(if (fifo) Set(0) else 0.to(st.august.length() - 1))
    val h = st.august[i]
    val rest = st.august.slice(0, i).concat(st.august.slice(i + 1, st.august.length()))
    st' = st.with("real", toDoor(h.dir)).with("august", rest)
            .with("busy", if (h.cur) false else st.busy)
            .with("tr", if (h.cur) Ble else st.tr)
            .with("shown", if (h.cur) asShown(toDoor(h.dir)) else st.shown)
  }

  action step = any { tap, bleWrites, bleReplies, bleFalls, timeOut, keepAliveExpired, augustRuns }

  // The screen is quiet and August holds nothing: what it shows is true, or it says it does not know.
  val quiet: bool = not(st.busy) and st.august.length() == 0
  val screenHonest: bool = not(quiet) or st.shown == SUnknown or st.shown == asShown(st.real)
  val honestOrWarned: bool = not(quiet) or st.shown == SUnknown or st.shown == asShown(st.real) or st.warned
}

module ghostBefore   { import ghost_order(fifo = true,  warnOnGhost = false, cloudAfterCloud = false, keepAliveUnknown = false).* }
module ghostBeforeAnyOrder  { import ghost_order(fifo = false, warnOnGhost = false, cloudAfterCloud = false, keepAliveUnknown = false).* }
module ghostKeepAliveOnly     { import ghost_order(fifo = true,  warnOnGhost = false, cloudAfterCloud = false, keepAliveUnknown = true).* }
module ghostWarned   { import ghost_order(fifo = true,  warnOnGhost = true,  cloudAfterCloud = false, keepAliveUnknown = true).* }
module ghostWarnedAnyOrder   { import ghost_order(fifo = false, warnOnGhost = true,  cloudAfterCloud = false, keepAliveUnknown = true).* }
